// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The file format of the data in S3.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FileFormat {
    /// <p>The file is in .CSV format.</p>
    pub csv: ::std::option::Option<crate::types::Csv>,
    /// <p>The file is in parquet format.</p>
    pub parquet: ::std::option::Option<crate::types::Parquet>,
}
impl FileFormat {
    /// <p>The file is in .CSV format.</p>
    pub fn csv(&self) -> ::std::option::Option<&crate::types::Csv> {
        self.csv.as_ref()
    }
    /// <p>The file is in parquet format.</p>
    pub fn parquet(&self) -> ::std::option::Option<&crate::types::Parquet> {
        self.parquet.as_ref()
    }
}
impl FileFormat {
    /// Creates a new builder-style object to manufacture [`FileFormat`](crate::types::FileFormat).
    pub fn builder() -> crate::types::builders::FileFormatBuilder {
        crate::types::builders::FileFormatBuilder::default()
    }
}

/// A builder for [`FileFormat`](crate::types::FileFormat).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FileFormatBuilder {
    pub(crate) csv: ::std::option::Option<crate::types::Csv>,
    pub(crate) parquet: ::std::option::Option<crate::types::Parquet>,
}
impl FileFormatBuilder {
    /// <p>The file is in .CSV format.</p>
    pub fn csv(mut self, input: crate::types::Csv) -> Self {
        self.csv = ::std::option::Option::Some(input);
        self
    }
    /// <p>The file is in .CSV format.</p>
    pub fn set_csv(mut self, input: ::std::option::Option<crate::types::Csv>) -> Self {
        self.csv = input;
        self
    }
    /// <p>The file is in .CSV format.</p>
    pub fn get_csv(&self) -> &::std::option::Option<crate::types::Csv> {
        &self.csv
    }
    /// <p>The file is in parquet format.</p>
    pub fn parquet(mut self, input: crate::types::Parquet) -> Self {
        self.parquet = ::std::option::Option::Some(input);
        self
    }
    /// <p>The file is in parquet format.</p>
    pub fn set_parquet(mut self, input: ::std::option::Option<crate::types::Parquet>) -> Self {
        self.parquet = input;
        self
    }
    /// <p>The file is in parquet format.</p>
    pub fn get_parquet(&self) -> &::std::option::Option<crate::types::Parquet> {
        &self.parquet
    }
    /// Consumes the builder and constructs a [`FileFormat`](crate::types::FileFormat).
    pub fn build(self) -> crate::types::FileFormat {
        crate::types::FileFormat {
            csv: self.csv,
            parquet: self.parquet,
        }
    }
}
