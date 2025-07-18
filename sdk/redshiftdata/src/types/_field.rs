// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A data value in a column.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum Field {
    /// <p>A value of the BLOB data type.</p>
    BlobValue(::aws_smithy_types::Blob),
    /// <p>A value of the Boolean data type.</p>
    BooleanValue(bool),
    /// <p>A value of the double data type.</p>
    DoubleValue(f64),
    /// <p>A value that indicates whether the data is NULL.</p>
    IsNull(bool),
    /// <p>A value of the long data type.</p>
    LongValue(i64),
    /// <p>A value of the string data type.</p>
    StringValue(::std::string::String),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl Field {
    /// Tries to convert the enum instance into [`BlobValue`](crate::types::Field::BlobValue), extracting the inner [`Blob`](::aws_smithy_types::Blob).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_blob_value(&self) -> ::std::result::Result<&::aws_smithy_types::Blob, &Self> {
        if let Field::BlobValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`BlobValue`](crate::types::Field::BlobValue).
    pub fn is_blob_value(&self) -> bool {
        self.as_blob_value().is_ok()
    }
    /// Tries to convert the enum instance into [`BooleanValue`](crate::types::Field::BooleanValue), extracting the inner [`bool`](bool).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_boolean_value(&self) -> ::std::result::Result<&bool, &Self> {
        if let Field::BooleanValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`BooleanValue`](crate::types::Field::BooleanValue).
    pub fn is_boolean_value(&self) -> bool {
        self.as_boolean_value().is_ok()
    }
    /// Tries to convert the enum instance into [`DoubleValue`](crate::types::Field::DoubleValue), extracting the inner [`f64`](f64).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_double_value(&self) -> ::std::result::Result<&f64, &Self> {
        if let Field::DoubleValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DoubleValue`](crate::types::Field::DoubleValue).
    pub fn is_double_value(&self) -> bool {
        self.as_double_value().is_ok()
    }
    /// Tries to convert the enum instance into [`IsNull`](crate::types::Field::IsNull), extracting the inner [`bool`](bool).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_is_null(&self) -> ::std::result::Result<&bool, &Self> {
        if let Field::IsNull(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`IsNull`](crate::types::Field::IsNull).
    pub fn is_is_null(&self) -> bool {
        self.as_is_null().is_ok()
    }
    /// Tries to convert the enum instance into [`LongValue`](crate::types::Field::LongValue), extracting the inner [`i64`](i64).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_long_value(&self) -> ::std::result::Result<&i64, &Self> {
        if let Field::LongValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LongValue`](crate::types::Field::LongValue).
    pub fn is_long_value(&self) -> bool {
        self.as_long_value().is_ok()
    }
    /// Tries to convert the enum instance into [`StringValue`](crate::types::Field::StringValue), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_string_value(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let Field::StringValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`StringValue`](crate::types::Field::StringValue).
    pub fn is_string_value(&self) -> bool {
        self.as_string_value().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
