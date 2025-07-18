// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A serializer to use for converting data to the Parquet format before storing it in Amazon S3. For more information, see <a href="https://parquet.apache.org/docs/">Apache Parquet</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParquetSerDe {
    /// <p>The Hadoop Distributed File System (HDFS) block size. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 256 MiB and the minimum is 64 MiB. Firehose uses this value for padding calculations.</p>
    pub block_size_bytes: ::std::option::Option<i32>,
    /// <p>The Parquet page size. Column chunks are divided into pages. A page is conceptually an indivisible unit (in terms of compression and encoding). The minimum value is 64 KiB and the default is 1 MiB.</p>
    pub page_size_bytes: ::std::option::Option<i32>,
    /// <p>The compression code to use over data blocks. The possible values are <code>UNCOMPRESSED</code>, <code>SNAPPY</code>, and <code>GZIP</code>, with the default being <code>SNAPPY</code>. Use <code>SNAPPY</code> for higher decompression speed. Use <code>GZIP</code> if the compression ratio is more important than speed.</p>
    pub compression: ::std::option::Option<crate::types::ParquetCompression>,
    /// <p>Indicates whether to enable dictionary compression.</p>
    pub enable_dictionary_compression: ::std::option::Option<bool>,
    /// <p>The maximum amount of padding to apply. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 0.</p>
    pub max_padding_bytes: ::std::option::Option<i32>,
    /// <p>Indicates the version of row format to output. The possible values are <code>V1</code> and <code>V2</code>. The default is <code>V1</code>.</p>
    pub writer_version: ::std::option::Option<crate::types::ParquetWriterVersion>,
}
impl ParquetSerDe {
    /// <p>The Hadoop Distributed File System (HDFS) block size. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 256 MiB and the minimum is 64 MiB. Firehose uses this value for padding calculations.</p>
    pub fn block_size_bytes(&self) -> ::std::option::Option<i32> {
        self.block_size_bytes
    }
    /// <p>The Parquet page size. Column chunks are divided into pages. A page is conceptually an indivisible unit (in terms of compression and encoding). The minimum value is 64 KiB and the default is 1 MiB.</p>
    pub fn page_size_bytes(&self) -> ::std::option::Option<i32> {
        self.page_size_bytes
    }
    /// <p>The compression code to use over data blocks. The possible values are <code>UNCOMPRESSED</code>, <code>SNAPPY</code>, and <code>GZIP</code>, with the default being <code>SNAPPY</code>. Use <code>SNAPPY</code> for higher decompression speed. Use <code>GZIP</code> if the compression ratio is more important than speed.</p>
    pub fn compression(&self) -> ::std::option::Option<&crate::types::ParquetCompression> {
        self.compression.as_ref()
    }
    /// <p>Indicates whether to enable dictionary compression.</p>
    pub fn enable_dictionary_compression(&self) -> ::std::option::Option<bool> {
        self.enable_dictionary_compression
    }
    /// <p>The maximum amount of padding to apply. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 0.</p>
    pub fn max_padding_bytes(&self) -> ::std::option::Option<i32> {
        self.max_padding_bytes
    }
    /// <p>Indicates the version of row format to output. The possible values are <code>V1</code> and <code>V2</code>. The default is <code>V1</code>.</p>
    pub fn writer_version(&self) -> ::std::option::Option<&crate::types::ParquetWriterVersion> {
        self.writer_version.as_ref()
    }
}
impl ParquetSerDe {
    /// Creates a new builder-style object to manufacture [`ParquetSerDe`](crate::types::ParquetSerDe).
    pub fn builder() -> crate::types::builders::ParquetSerDeBuilder {
        crate::types::builders::ParquetSerDeBuilder::default()
    }
}

/// A builder for [`ParquetSerDe`](crate::types::ParquetSerDe).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParquetSerDeBuilder {
    pub(crate) block_size_bytes: ::std::option::Option<i32>,
    pub(crate) page_size_bytes: ::std::option::Option<i32>,
    pub(crate) compression: ::std::option::Option<crate::types::ParquetCompression>,
    pub(crate) enable_dictionary_compression: ::std::option::Option<bool>,
    pub(crate) max_padding_bytes: ::std::option::Option<i32>,
    pub(crate) writer_version: ::std::option::Option<crate::types::ParquetWriterVersion>,
}
impl ParquetSerDeBuilder {
    /// <p>The Hadoop Distributed File System (HDFS) block size. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 256 MiB and the minimum is 64 MiB. Firehose uses this value for padding calculations.</p>
    pub fn block_size_bytes(mut self, input: i32) -> Self {
        self.block_size_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Hadoop Distributed File System (HDFS) block size. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 256 MiB and the minimum is 64 MiB. Firehose uses this value for padding calculations.</p>
    pub fn set_block_size_bytes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.block_size_bytes = input;
        self
    }
    /// <p>The Hadoop Distributed File System (HDFS) block size. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 256 MiB and the minimum is 64 MiB. Firehose uses this value for padding calculations.</p>
    pub fn get_block_size_bytes(&self) -> &::std::option::Option<i32> {
        &self.block_size_bytes
    }
    /// <p>The Parquet page size. Column chunks are divided into pages. A page is conceptually an indivisible unit (in terms of compression and encoding). The minimum value is 64 KiB and the default is 1 MiB.</p>
    pub fn page_size_bytes(mut self, input: i32) -> Self {
        self.page_size_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Parquet page size. Column chunks are divided into pages. A page is conceptually an indivisible unit (in terms of compression and encoding). The minimum value is 64 KiB and the default is 1 MiB.</p>
    pub fn set_page_size_bytes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size_bytes = input;
        self
    }
    /// <p>The Parquet page size. Column chunks are divided into pages. A page is conceptually an indivisible unit (in terms of compression and encoding). The minimum value is 64 KiB and the default is 1 MiB.</p>
    pub fn get_page_size_bytes(&self) -> &::std::option::Option<i32> {
        &self.page_size_bytes
    }
    /// <p>The compression code to use over data blocks. The possible values are <code>UNCOMPRESSED</code>, <code>SNAPPY</code>, and <code>GZIP</code>, with the default being <code>SNAPPY</code>. Use <code>SNAPPY</code> for higher decompression speed. Use <code>GZIP</code> if the compression ratio is more important than speed.</p>
    pub fn compression(mut self, input: crate::types::ParquetCompression) -> Self {
        self.compression = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compression code to use over data blocks. The possible values are <code>UNCOMPRESSED</code>, <code>SNAPPY</code>, and <code>GZIP</code>, with the default being <code>SNAPPY</code>. Use <code>SNAPPY</code> for higher decompression speed. Use <code>GZIP</code> if the compression ratio is more important than speed.</p>
    pub fn set_compression(mut self, input: ::std::option::Option<crate::types::ParquetCompression>) -> Self {
        self.compression = input;
        self
    }
    /// <p>The compression code to use over data blocks. The possible values are <code>UNCOMPRESSED</code>, <code>SNAPPY</code>, and <code>GZIP</code>, with the default being <code>SNAPPY</code>. Use <code>SNAPPY</code> for higher decompression speed. Use <code>GZIP</code> if the compression ratio is more important than speed.</p>
    pub fn get_compression(&self) -> &::std::option::Option<crate::types::ParquetCompression> {
        &self.compression
    }
    /// <p>Indicates whether to enable dictionary compression.</p>
    pub fn enable_dictionary_compression(mut self, input: bool) -> Self {
        self.enable_dictionary_compression = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to enable dictionary compression.</p>
    pub fn set_enable_dictionary_compression(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_dictionary_compression = input;
        self
    }
    /// <p>Indicates whether to enable dictionary compression.</p>
    pub fn get_enable_dictionary_compression(&self) -> &::std::option::Option<bool> {
        &self.enable_dictionary_compression
    }
    /// <p>The maximum amount of padding to apply. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 0.</p>
    pub fn max_padding_bytes(mut self, input: i32) -> Self {
        self.max_padding_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of padding to apply. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 0.</p>
    pub fn set_max_padding_bytes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_padding_bytes = input;
        self
    }
    /// <p>The maximum amount of padding to apply. This is useful if you intend to copy the data from Amazon S3 to HDFS before querying. The default is 0.</p>
    pub fn get_max_padding_bytes(&self) -> &::std::option::Option<i32> {
        &self.max_padding_bytes
    }
    /// <p>Indicates the version of row format to output. The possible values are <code>V1</code> and <code>V2</code>. The default is <code>V1</code>.</p>
    pub fn writer_version(mut self, input: crate::types::ParquetWriterVersion) -> Self {
        self.writer_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the version of row format to output. The possible values are <code>V1</code> and <code>V2</code>. The default is <code>V1</code>.</p>
    pub fn set_writer_version(mut self, input: ::std::option::Option<crate::types::ParquetWriterVersion>) -> Self {
        self.writer_version = input;
        self
    }
    /// <p>Indicates the version of row format to output. The possible values are <code>V1</code> and <code>V2</code>. The default is <code>V1</code>.</p>
    pub fn get_writer_version(&self) -> &::std::option::Option<crate::types::ParquetWriterVersion> {
        &self.writer_version
    }
    /// Consumes the builder and constructs a [`ParquetSerDe`](crate::types::ParquetSerDe).
    pub fn build(self) -> crate::types::ParquetSerDe {
        crate::types::ParquetSerDe {
            block_size_bytes: self.block_size_bytes,
            page_size_bytes: self.page_size_bytes,
            compression: self.compression,
            enable_dictionary_compression: self.enable_dictionary_compression,
            max_padding_bytes: self.max_padding_bytes,
            writer_version: self.writer_version,
        }
    }
}
