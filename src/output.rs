//! Output destinations for audit logs.

use crate::config::{OutputConfig, SyslogFacility, SyslogProtocol};
use async_trait::async_trait;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error};

/// Error type for output operations.
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[cfg(feature = "http-output")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Output closed")]
    Closed,
}

/// Trait for log output destinations.
#[async_trait]
pub trait Output: Send + Sync {
    /// Write a log line to this output.
    async fn write(&self, line: &str) -> Result<(), OutputError>;

    /// Flush any buffered data.
    async fn flush(&self) -> Result<(), OutputError>;

    /// Close the output.
    async fn close(&self) -> Result<(), OutputError>;
}

/// Create outputs from configuration.
pub async fn create_outputs(configs: &[OutputConfig]) -> Vec<Arc<dyn Output>> {
    let mut outputs: Vec<Arc<dyn Output>> = Vec::new();

    for config in configs {
        match create_output(config).await {
            Ok(output) => outputs.push(output),
            Err(e) => {
                error!("Failed to create output: {}", e);
            }
        }
    }

    // Ensure at least stdout if no outputs configured
    if outputs.is_empty() {
        outputs.push(Arc::new(StdoutOutput));
    }

    outputs
}

async fn create_output(config: &OutputConfig) -> Result<Arc<dyn Output>, OutputError> {
    match config {
        OutputConfig::Stdout => Ok(Arc::new(StdoutOutput)),
        OutputConfig::Stderr => Ok(Arc::new(StderrOutput)),
        OutputConfig::File {
            path,
            max_size,
            max_files,
        } => {
            let output = FileOutput::new(path.clone(), *max_size, *max_files).await?;
            Ok(Arc::new(output))
        }
        OutputConfig::Syslog {
            address,
            protocol,
            facility,
        } => {
            let output = SyslogOutput::new(address, *protocol, *facility).await?;
            Ok(Arc::new(output))
        }
        #[cfg(feature = "http-output")]
        OutputConfig::Http {
            url,
            method,
            headers,
            batch_size,
            flush_interval_secs,
            timeout_secs,
            retries,
        } => {
            let output = HttpOutput::new(
                url.clone(),
                *method,
                headers.clone(),
                *batch_size,
                *flush_interval_secs,
                *timeout_secs,
                *retries,
            );
            Ok(Arc::new(output))
        }
        #[cfg(feature = "kafka-output")]
        OutputConfig::Kafka { .. } => {
            // Kafka implementation would go here
            warn!("Kafka output not yet implemented, using stdout");
            Ok(Arc::new(StdoutOutput))
        }
    }
}

/// Stdout output.
pub struct StdoutOutput;

#[async_trait]
impl Output for StdoutOutput {
    async fn write(&self, line: &str) -> Result<(), OutputError> {
        println!("{}", line);
        Ok(())
    }

    async fn flush(&self) -> Result<(), OutputError> {
        std::io::stdout().flush()?;
        Ok(())
    }

    async fn close(&self) -> Result<(), OutputError> {
        Ok(())
    }
}

/// Stderr output.
pub struct StderrOutput;

#[async_trait]
impl Output for StderrOutput {
    async fn write(&self, line: &str) -> Result<(), OutputError> {
        eprintln!("{}", line);
        Ok(())
    }

    async fn flush(&self) -> Result<(), OutputError> {
        std::io::stderr().flush()?;
        Ok(())
    }

    async fn close(&self) -> Result<(), OutputError> {
        Ok(())
    }
}

/// File output with optional rotation.
pub struct FileOutput {
    path: PathBuf,
    file: Mutex<File>,
    max_size: Option<u64>,
    max_files: Option<u32>,
    current_size: Mutex<u64>,
}

impl FileOutput {
    pub async fn new(
        path: PathBuf,
        max_size: Option<u64>,
        max_files: Option<u32>,
    ) -> Result<Self, OutputError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;

        let metadata = file.metadata().await?;
        let current_size = metadata.len();

        Ok(Self {
            path,
            file: Mutex::new(file),
            max_size,
            max_files,
            current_size: Mutex::new(current_size),
        })
    }

    async fn rotate(&self) -> Result<(), OutputError> {
        let max_files = self.max_files.unwrap_or(5);

        // Rename existing rotated files
        for i in (1..max_files).rev() {
            let from = self.rotated_path(i);
            let to = self.rotated_path(i + 1);
            if from.exists() {
                if i + 1 >= max_files {
                    // Delete oldest file
                    tokio::fs::remove_file(&from).await.ok();
                } else {
                    tokio::fs::rename(&from, &to).await.ok();
                }
            }
        }

        // Rename current file to .1
        let rotated = self.rotated_path(1);
        tokio::fs::rename(&self.path, &rotated).await?;

        // Create new file
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;

        let mut file = self.file.lock().await;
        *file = new_file;

        let mut size = self.current_size.lock().await;
        *size = 0;

        debug!(path = %self.path.display(), "Rotated log file");

        Ok(())
    }

    fn rotated_path(&self, index: u32) -> PathBuf {
        let mut path = self.path.clone();
        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();

        if extension.is_empty() {
            path.set_extension(format!("{}", index));
        } else {
            path.set_extension(format!("{}.{}", extension, index));
        }

        path
    }
}

#[async_trait]
impl Output for FileOutput {
    async fn write(&self, line: &str) -> Result<(), OutputError> {
        let line_with_newline = format!("{}\n", line);
        let bytes = line_with_newline.as_bytes();

        // Check if rotation is needed
        if let Some(max_size) = self.max_size {
            let current = *self.current_size.lock().await;
            if current + bytes.len() as u64 > max_size {
                self.rotate().await?;
            }
        }

        let mut file = self.file.lock().await;
        file.write_all(bytes).await?;

        let mut size = self.current_size.lock().await;
        *size += bytes.len() as u64;

        Ok(())
    }

    async fn flush(&self) -> Result<(), OutputError> {
        let mut file = self.file.lock().await;
        file.flush().await?;
        Ok(())
    }

    async fn close(&self) -> Result<(), OutputError> {
        self.flush().await?;
        Ok(())
    }
}

/// Syslog output (UDP or TCP).
pub struct SyslogOutput {
    #[allow(dead_code)]
    address: String,
    protocol: SyslogProtocol,
    facility: SyslogFacility,
    udp_socket: Option<Mutex<UdpSocket>>,
    tcp_stream: Option<Mutex<TcpStream>>,
}

impl SyslogOutput {
    pub async fn new(
        address: &str,
        protocol: SyslogProtocol,
        facility: SyslogFacility,
    ) -> Result<Self, OutputError> {
        match protocol {
            SyslogProtocol::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.connect(address).await?;
                Ok(Self {
                    address: address.to_string(),
                    protocol,
                    facility,
                    udp_socket: Some(Mutex::new(socket)),
                    tcp_stream: None,
                })
            }
            SyslogProtocol::Tcp => {
                let stream = TcpStream::connect(address).await?;
                Ok(Self {
                    address: address.to_string(),
                    protocol,
                    facility,
                    udp_socket: None,
                    tcp_stream: Some(Mutex::new(stream)),
                })
            }
        }
    }

    /// Format a syslog message (RFC 5424 simplified).
    fn format_syslog(&self, message: &str) -> String {
        // Priority = facility * 8 + severity
        // Using severity 6 (informational) for audit logs
        let priority = self.facility.code() * 8 + 6;

        // Simplified syslog format
        format!("<{}>1 - - zentinel-audit - - - {}", priority, message)
    }
}

#[async_trait]
impl Output for SyslogOutput {
    async fn write(&self, line: &str) -> Result<(), OutputError> {
        let message = self.format_syslog(line);
        let bytes = message.as_bytes();

        match self.protocol {
            SyslogProtocol::Udp => {
                if let Some(ref socket) = self.udp_socket {
                    let socket = socket.lock().await;
                    socket.send(bytes).await?;
                }
            }
            SyslogProtocol::Tcp => {
                if let Some(ref stream) = self.tcp_stream {
                    let mut stream = stream.lock().await;
                    stream.write_all(bytes).await?;
                    stream.write_all(b"\n").await?;
                }
            }
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), OutputError> {
        if let Some(ref stream) = self.tcp_stream {
            let mut stream = stream.lock().await;
            stream.flush().await?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<(), OutputError> {
        self.flush().await?;
        Ok(())
    }
}

/// HTTP webhook output.
#[cfg(feature = "http-output")]
pub struct HttpOutput {
    client: reqwest::Client,
    url: String,
    method: crate::config::HttpMethod,
    headers: std::collections::HashMap<String, String>,
    batch: Mutex<Vec<String>>,
    batch_size: usize,
    retries: u32,
}

#[cfg(feature = "http-output")]
impl HttpOutput {
    pub fn new(
        url: String,
        method: crate::config::HttpMethod,
        headers: std::collections::HashMap<String, String>,
        batch_size: usize,
        _flush_interval_secs: u64,
        timeout_secs: u64,
        retries: u32,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            client,
            url,
            method,
            headers,
            batch: Mutex::new(Vec::new()),
            batch_size: batch_size.max(1),
            retries,
        }
    }

    async fn send_batch(&self, batch: Vec<String>) -> Result<(), OutputError> {
        if batch.is_empty() {
            return Ok(());
        }

        let body = if batch.len() == 1 {
            batch[0].clone()
        } else {
            // Send as JSON array
            serde_json::to_string(&batch)?
        };

        let mut request = match self.method {
            crate::config::HttpMethod::Post => self.client.post(&self.url),
            crate::config::HttpMethod::Put => self.client.put(&self.url),
        };

        request = request
            .header("Content-Type", "application/json")
            .body(body);

        for (key, value) in &self.headers {
            request = request.header(key, value);
        }

        let mut last_error = None;
        for attempt in 0..=self.retries {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(100 * (1 << attempt))).await;
            }

            match request.try_clone().unwrap().send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    } else {
                        last_error = Some(OutputError::Network(format!(
                            "HTTP {} from webhook",
                            response.status()
                        )));
                    }
                }
                Err(e) => {
                    last_error = Some(OutputError::Http(e));
                }
            }
        }

        Err(last_error.unwrap_or(OutputError::Network("Unknown error".to_string())))
    }
}

#[cfg(feature = "http-output")]
#[async_trait]
impl Output for HttpOutput {
    async fn write(&self, line: &str) -> Result<(), OutputError> {
        let mut batch = self.batch.lock().await;
        batch.push(line.to_string());

        if batch.len() >= self.batch_size {
            let to_send = std::mem::take(&mut *batch);
            drop(batch); // Release lock before sending
            self.send_batch(to_send).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), OutputError> {
        let mut batch = self.batch.lock().await;
        if !batch.is_empty() {
            let to_send = std::mem::take(&mut *batch);
            drop(batch);
            self.send_batch(to_send).await?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<(), OutputError> {
        self.flush().await
    }
}

/// Multi-output that writes to multiple destinations.
pub struct MultiOutput {
    outputs: Vec<Arc<dyn Output>>,
}

impl MultiOutput {
    pub fn new(outputs: Vec<Arc<dyn Output>>) -> Self {
        Self { outputs }
    }
}

#[async_trait]
impl Output for MultiOutput {
    async fn write(&self, line: &str) -> Result<(), OutputError> {
        for output in &self.outputs {
            if let Err(e) = output.write(line).await {
                error!("Output error: {}", e);
                // Continue writing to other outputs
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), OutputError> {
        for output in &self.outputs {
            output.flush().await?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<(), OutputError> {
        for output in &self.outputs {
            output.close().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_stdout_output() {
        let output = StdoutOutput;
        assert!(output.write("test message").await.is_ok());
    }

    #[tokio::test]
    async fn test_file_output() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("audit.log");

        let output = FileOutput::new(path.clone(), None, None).await.unwrap();
        output.write("line 1").await.unwrap();
        output.write("line 2").await.unwrap();
        output.flush().await.unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(content.contains("line 1"));
        assert!(content.contains("line 2"));
    }

    #[tokio::test]
    async fn test_file_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("audit.log");

        // Small max size to trigger rotation
        let output = FileOutput::new(path.clone(), Some(50), Some(3))
            .await
            .unwrap();

        // Write enough to trigger rotation
        for i in 0..10 {
            output
                .write(&format!("Line {} with some content", i))
                .await
                .unwrap();
        }
        output.flush().await.unwrap();

        // Check that rotated files exist
        assert!(path.exists());
        assert!(temp_dir.path().join("audit.log.1").exists());
    }

    #[tokio::test]
    async fn test_multi_output() {
        let output = MultiOutput::new(vec![Arc::new(StdoutOutput), Arc::new(StderrOutput)]);

        assert!(output.write("test to both").await.is_ok());
    }

    #[test]
    fn test_syslog_format() {
        // Can't easily test actual syslog connection, but test formatting
        let formatted = format!("<{}>1 - - zentinel-audit - - - test message", 14 * 8 + 6);
        assert!(formatted.starts_with("<"));
        assert!(formatted.contains("zentinel-audit"));
    }
}
