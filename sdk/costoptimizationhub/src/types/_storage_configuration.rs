// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The storage configuration used for recommendations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StorageConfiguration {
    /// <p>The storage type.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The storage volume.</p>
    pub size_in_gb: ::std::option::Option<f64>,
}
impl StorageConfiguration {
    /// <p>The storage type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The storage volume.</p>
    pub fn size_in_gb(&self) -> ::std::option::Option<f64> {
        self.size_in_gb
    }
}
impl StorageConfiguration {
    /// Creates a new builder-style object to manufacture [`StorageConfiguration`](crate::types::StorageConfiguration).
    pub fn builder() -> crate::types::builders::StorageConfigurationBuilder {
        crate::types::builders::StorageConfigurationBuilder::default()
    }
}

/// A builder for [`StorageConfiguration`](crate::types::StorageConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StorageConfigurationBuilder {
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) size_in_gb: ::std::option::Option<f64>,
}
impl StorageConfigurationBuilder {
    /// <p>The storage type.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The storage type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The storage type.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The storage volume.</p>
    pub fn size_in_gb(mut self, input: f64) -> Self {
        self.size_in_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>The storage volume.</p>
    pub fn set_size_in_gb(mut self, input: ::std::option::Option<f64>) -> Self {
        self.size_in_gb = input;
        self
    }
    /// <p>The storage volume.</p>
    pub fn get_size_in_gb(&self) -> &::std::option::Option<f64> {
        &self.size_in_gb
    }
    /// Consumes the builder and constructs a [`StorageConfiguration`](crate::types::StorageConfiguration).
    pub fn build(self) -> crate::types::StorageConfiguration {
        crate::types::StorageConfiguration {
            r#type: self.r#type,
            size_in_gb: self.size_in_gb,
        }
    }
}
