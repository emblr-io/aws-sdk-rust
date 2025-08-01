// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>References a Kubernetes secret resource. This name of the secret must start and end with an alphanumeric character, is required to be lowercase, can include periods (.) and hyphens (-), and can't contain more than 253 characters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImagePullSecret {
    /// <p>Provides a unique identifier for the <code>ImagePullSecret</code>. This object is required when <code>EksPodProperties$imagePullSecrets</code> is used.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl ImagePullSecret {
    /// <p>Provides a unique identifier for the <code>ImagePullSecret</code>. This object is required when <code>EksPodProperties$imagePullSecrets</code> is used.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl ImagePullSecret {
    /// Creates a new builder-style object to manufacture [`ImagePullSecret`](crate::types::ImagePullSecret).
    pub fn builder() -> crate::types::builders::ImagePullSecretBuilder {
        crate::types::builders::ImagePullSecretBuilder::default()
    }
}

/// A builder for [`ImagePullSecret`](crate::types::ImagePullSecret).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImagePullSecretBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl ImagePullSecretBuilder {
    /// <p>Provides a unique identifier for the <code>ImagePullSecret</code>. This object is required when <code>EksPodProperties$imagePullSecrets</code> is used.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides a unique identifier for the <code>ImagePullSecret</code>. This object is required when <code>EksPodProperties$imagePullSecrets</code> is used.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Provides a unique identifier for the <code>ImagePullSecret</code>. This object is required when <code>EksPodProperties$imagePullSecrets</code> is used.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`ImagePullSecret`](crate::types::ImagePullSecret).
    pub fn build(self) -> crate::types::ImagePullSecret {
        crate::types::ImagePullSecret { name: self.name }
    }
}
