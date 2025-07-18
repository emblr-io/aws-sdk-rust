// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFileCacheInput {
    /// <p>The ID of the cache that you are updating.</p>
    pub file_cache_id: ::std::option::Option<::std::string::String>,
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The configuration updates for an Amazon File Cache resource.</p>
    pub lustre_configuration: ::std::option::Option<crate::types::UpdateFileCacheLustreConfiguration>,
}
impl UpdateFileCacheInput {
    /// <p>The ID of the cache that you are updating.</p>
    pub fn file_cache_id(&self) -> ::std::option::Option<&str> {
        self.file_cache_id.as_deref()
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The configuration updates for an Amazon File Cache resource.</p>
    pub fn lustre_configuration(&self) -> ::std::option::Option<&crate::types::UpdateFileCacheLustreConfiguration> {
        self.lustre_configuration.as_ref()
    }
}
impl UpdateFileCacheInput {
    /// Creates a new builder-style object to manufacture [`UpdateFileCacheInput`](crate::operation::update_file_cache::UpdateFileCacheInput).
    pub fn builder() -> crate::operation::update_file_cache::builders::UpdateFileCacheInputBuilder {
        crate::operation::update_file_cache::builders::UpdateFileCacheInputBuilder::default()
    }
}

/// A builder for [`UpdateFileCacheInput`](crate::operation::update_file_cache::UpdateFileCacheInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFileCacheInputBuilder {
    pub(crate) file_cache_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) lustre_configuration: ::std::option::Option<crate::types::UpdateFileCacheLustreConfiguration>,
}
impl UpdateFileCacheInputBuilder {
    /// <p>The ID of the cache that you are updating.</p>
    /// This field is required.
    pub fn file_cache_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_cache_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the cache that you are updating.</p>
    pub fn set_file_cache_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_cache_id = input;
        self
    }
    /// <p>The ID of the cache that you are updating.</p>
    pub fn get_file_cache_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_cache_id
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>The configuration updates for an Amazon File Cache resource.</p>
    pub fn lustre_configuration(mut self, input: crate::types::UpdateFileCacheLustreConfiguration) -> Self {
        self.lustre_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration updates for an Amazon File Cache resource.</p>
    pub fn set_lustre_configuration(mut self, input: ::std::option::Option<crate::types::UpdateFileCacheLustreConfiguration>) -> Self {
        self.lustre_configuration = input;
        self
    }
    /// <p>The configuration updates for an Amazon File Cache resource.</p>
    pub fn get_lustre_configuration(&self) -> &::std::option::Option<crate::types::UpdateFileCacheLustreConfiguration> {
        &self.lustre_configuration
    }
    /// Consumes the builder and constructs a [`UpdateFileCacheInput`](crate::operation::update_file_cache::UpdateFileCacheInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_file_cache::UpdateFileCacheInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_file_cache::UpdateFileCacheInput {
            file_cache_id: self.file_cache_id,
            client_request_token: self.client_request_token,
            lustre_configuration: self.lustre_configuration,
        })
    }
}
