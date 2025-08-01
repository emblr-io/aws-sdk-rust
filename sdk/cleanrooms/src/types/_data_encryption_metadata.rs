// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings for client-side encryption for cryptographic computing.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataEncryptionMetadata {
    /// <p>Indicates whether encrypted tables can contain cleartext data (<code>TRUE</code>) or are to cryptographically process every column (<code>FALSE</code>).</p>
    pub allow_cleartext: bool,
    /// <p>Indicates whether Fingerprint columns can contain duplicate entries (<code>TRUE</code>) or are to contain only non-repeated values (<code>FALSE</code>).</p>
    pub allow_duplicates: bool,
    /// <p>Indicates whether Fingerprint columns can be joined on any other Fingerprint column with a different name (<code>TRUE</code>) or can only be joined on Fingerprint columns of the same name (<code>FALSE</code>).</p>
    pub allow_joins_on_columns_with_different_names: bool,
    /// <p>Indicates whether NULL values are to be copied as NULL to encrypted tables (<code>TRUE</code>) or cryptographically processed (<code>FALSE</code>).</p>
    pub preserve_nulls: bool,
}
impl DataEncryptionMetadata {
    /// <p>Indicates whether encrypted tables can contain cleartext data (<code>TRUE</code>) or are to cryptographically process every column (<code>FALSE</code>).</p>
    pub fn allow_cleartext(&self) -> bool {
        self.allow_cleartext
    }
    /// <p>Indicates whether Fingerprint columns can contain duplicate entries (<code>TRUE</code>) or are to contain only non-repeated values (<code>FALSE</code>).</p>
    pub fn allow_duplicates(&self) -> bool {
        self.allow_duplicates
    }
    /// <p>Indicates whether Fingerprint columns can be joined on any other Fingerprint column with a different name (<code>TRUE</code>) or can only be joined on Fingerprint columns of the same name (<code>FALSE</code>).</p>
    pub fn allow_joins_on_columns_with_different_names(&self) -> bool {
        self.allow_joins_on_columns_with_different_names
    }
    /// <p>Indicates whether NULL values are to be copied as NULL to encrypted tables (<code>TRUE</code>) or cryptographically processed (<code>FALSE</code>).</p>
    pub fn preserve_nulls(&self) -> bool {
        self.preserve_nulls
    }
}
impl DataEncryptionMetadata {
    /// Creates a new builder-style object to manufacture [`DataEncryptionMetadata`](crate::types::DataEncryptionMetadata).
    pub fn builder() -> crate::types::builders::DataEncryptionMetadataBuilder {
        crate::types::builders::DataEncryptionMetadataBuilder::default()
    }
}

/// A builder for [`DataEncryptionMetadata`](crate::types::DataEncryptionMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataEncryptionMetadataBuilder {
    pub(crate) allow_cleartext: ::std::option::Option<bool>,
    pub(crate) allow_duplicates: ::std::option::Option<bool>,
    pub(crate) allow_joins_on_columns_with_different_names: ::std::option::Option<bool>,
    pub(crate) preserve_nulls: ::std::option::Option<bool>,
}
impl DataEncryptionMetadataBuilder {
    /// <p>Indicates whether encrypted tables can contain cleartext data (<code>TRUE</code>) or are to cryptographically process every column (<code>FALSE</code>).</p>
    /// This field is required.
    pub fn allow_cleartext(mut self, input: bool) -> Self {
        self.allow_cleartext = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether encrypted tables can contain cleartext data (<code>TRUE</code>) or are to cryptographically process every column (<code>FALSE</code>).</p>
    pub fn set_allow_cleartext(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_cleartext = input;
        self
    }
    /// <p>Indicates whether encrypted tables can contain cleartext data (<code>TRUE</code>) or are to cryptographically process every column (<code>FALSE</code>).</p>
    pub fn get_allow_cleartext(&self) -> &::std::option::Option<bool> {
        &self.allow_cleartext
    }
    /// <p>Indicates whether Fingerprint columns can contain duplicate entries (<code>TRUE</code>) or are to contain only non-repeated values (<code>FALSE</code>).</p>
    /// This field is required.
    pub fn allow_duplicates(mut self, input: bool) -> Self {
        self.allow_duplicates = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether Fingerprint columns can contain duplicate entries (<code>TRUE</code>) or are to contain only non-repeated values (<code>FALSE</code>).</p>
    pub fn set_allow_duplicates(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_duplicates = input;
        self
    }
    /// <p>Indicates whether Fingerprint columns can contain duplicate entries (<code>TRUE</code>) or are to contain only non-repeated values (<code>FALSE</code>).</p>
    pub fn get_allow_duplicates(&self) -> &::std::option::Option<bool> {
        &self.allow_duplicates
    }
    /// <p>Indicates whether Fingerprint columns can be joined on any other Fingerprint column with a different name (<code>TRUE</code>) or can only be joined on Fingerprint columns of the same name (<code>FALSE</code>).</p>
    /// This field is required.
    pub fn allow_joins_on_columns_with_different_names(mut self, input: bool) -> Self {
        self.allow_joins_on_columns_with_different_names = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether Fingerprint columns can be joined on any other Fingerprint column with a different name (<code>TRUE</code>) or can only be joined on Fingerprint columns of the same name (<code>FALSE</code>).</p>
    pub fn set_allow_joins_on_columns_with_different_names(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_joins_on_columns_with_different_names = input;
        self
    }
    /// <p>Indicates whether Fingerprint columns can be joined on any other Fingerprint column with a different name (<code>TRUE</code>) or can only be joined on Fingerprint columns of the same name (<code>FALSE</code>).</p>
    pub fn get_allow_joins_on_columns_with_different_names(&self) -> &::std::option::Option<bool> {
        &self.allow_joins_on_columns_with_different_names
    }
    /// <p>Indicates whether NULL values are to be copied as NULL to encrypted tables (<code>TRUE</code>) or cryptographically processed (<code>FALSE</code>).</p>
    /// This field is required.
    pub fn preserve_nulls(mut self, input: bool) -> Self {
        self.preserve_nulls = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether NULL values are to be copied as NULL to encrypted tables (<code>TRUE</code>) or cryptographically processed (<code>FALSE</code>).</p>
    pub fn set_preserve_nulls(mut self, input: ::std::option::Option<bool>) -> Self {
        self.preserve_nulls = input;
        self
    }
    /// <p>Indicates whether NULL values are to be copied as NULL to encrypted tables (<code>TRUE</code>) or cryptographically processed (<code>FALSE</code>).</p>
    pub fn get_preserve_nulls(&self) -> &::std::option::Option<bool> {
        &self.preserve_nulls
    }
    /// Consumes the builder and constructs a [`DataEncryptionMetadata`](crate::types::DataEncryptionMetadata).
    /// This method will fail if any of the following fields are not set:
    /// - [`allow_cleartext`](crate::types::builders::DataEncryptionMetadataBuilder::allow_cleartext)
    /// - [`allow_duplicates`](crate::types::builders::DataEncryptionMetadataBuilder::allow_duplicates)
    /// - [`allow_joins_on_columns_with_different_names`](crate::types::builders::DataEncryptionMetadataBuilder::allow_joins_on_columns_with_different_names)
    /// - [`preserve_nulls`](crate::types::builders::DataEncryptionMetadataBuilder::preserve_nulls)
    pub fn build(self) -> ::std::result::Result<crate::types::DataEncryptionMetadata, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataEncryptionMetadata {
            allow_cleartext: self.allow_cleartext.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "allow_cleartext",
                    "allow_cleartext was not specified but it is required when building DataEncryptionMetadata",
                )
            })?,
            allow_duplicates: self.allow_duplicates.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "allow_duplicates",
                    "allow_duplicates was not specified but it is required when building DataEncryptionMetadata",
                )
            })?,
            allow_joins_on_columns_with_different_names: self.allow_joins_on_columns_with_different_names.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "allow_joins_on_columns_with_different_names",
                    "allow_joins_on_columns_with_different_names was not specified but it is required when building DataEncryptionMetadata",
                )
            })?,
            preserve_nulls: self.preserve_nulls.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "preserve_nulls",
                    "preserve_nulls was not specified but it is required when building DataEncryptionMetadata",
                )
            })?,
        })
    }
}
