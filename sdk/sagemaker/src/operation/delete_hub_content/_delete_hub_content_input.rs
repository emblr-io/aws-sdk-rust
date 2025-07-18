// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteHubContentInput {
    /// <p>The name of the hub that you want to delete content in.</p>
    pub hub_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of content that you want to delete from a hub.</p>
    pub hub_content_type: ::std::option::Option<crate::types::HubContentType>,
    /// <p>The name of the content that you want to delete from a hub.</p>
    pub hub_content_name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the content that you want to delete from a hub.</p>
    pub hub_content_version: ::std::option::Option<::std::string::String>,
}
impl DeleteHubContentInput {
    /// <p>The name of the hub that you want to delete content in.</p>
    pub fn hub_name(&self) -> ::std::option::Option<&str> {
        self.hub_name.as_deref()
    }
    /// <p>The type of content that you want to delete from a hub.</p>
    pub fn hub_content_type(&self) -> ::std::option::Option<&crate::types::HubContentType> {
        self.hub_content_type.as_ref()
    }
    /// <p>The name of the content that you want to delete from a hub.</p>
    pub fn hub_content_name(&self) -> ::std::option::Option<&str> {
        self.hub_content_name.as_deref()
    }
    /// <p>The version of the content that you want to delete from a hub.</p>
    pub fn hub_content_version(&self) -> ::std::option::Option<&str> {
        self.hub_content_version.as_deref()
    }
}
impl DeleteHubContentInput {
    /// Creates a new builder-style object to manufacture [`DeleteHubContentInput`](crate::operation::delete_hub_content::DeleteHubContentInput).
    pub fn builder() -> crate::operation::delete_hub_content::builders::DeleteHubContentInputBuilder {
        crate::operation::delete_hub_content::builders::DeleteHubContentInputBuilder::default()
    }
}

/// A builder for [`DeleteHubContentInput`](crate::operation::delete_hub_content::DeleteHubContentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteHubContentInputBuilder {
    pub(crate) hub_name: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_type: ::std::option::Option<crate::types::HubContentType>,
    pub(crate) hub_content_name: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_version: ::std::option::Option<::std::string::String>,
}
impl DeleteHubContentInputBuilder {
    /// <p>The name of the hub that you want to delete content in.</p>
    /// This field is required.
    pub fn hub_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the hub that you want to delete content in.</p>
    pub fn set_hub_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_name = input;
        self
    }
    /// <p>The name of the hub that you want to delete content in.</p>
    pub fn get_hub_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_name
    }
    /// <p>The type of content that you want to delete from a hub.</p>
    /// This field is required.
    pub fn hub_content_type(mut self, input: crate::types::HubContentType) -> Self {
        self.hub_content_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of content that you want to delete from a hub.</p>
    pub fn set_hub_content_type(mut self, input: ::std::option::Option<crate::types::HubContentType>) -> Self {
        self.hub_content_type = input;
        self
    }
    /// <p>The type of content that you want to delete from a hub.</p>
    pub fn get_hub_content_type(&self) -> &::std::option::Option<crate::types::HubContentType> {
        &self.hub_content_type
    }
    /// <p>The name of the content that you want to delete from a hub.</p>
    /// This field is required.
    pub fn hub_content_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_content_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the content that you want to delete from a hub.</p>
    pub fn set_hub_content_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_content_name = input;
        self
    }
    /// <p>The name of the content that you want to delete from a hub.</p>
    pub fn get_hub_content_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_content_name
    }
    /// <p>The version of the content that you want to delete from a hub.</p>
    /// This field is required.
    pub fn hub_content_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_content_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the content that you want to delete from a hub.</p>
    pub fn set_hub_content_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_content_version = input;
        self
    }
    /// <p>The version of the content that you want to delete from a hub.</p>
    pub fn get_hub_content_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_content_version
    }
    /// Consumes the builder and constructs a [`DeleteHubContentInput`](crate::operation::delete_hub_content::DeleteHubContentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_hub_content::DeleteHubContentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_hub_content::DeleteHubContentInput {
            hub_name: self.hub_name,
            hub_content_type: self.hub_content_type,
            hub_content_name: self.hub_content_name,
            hub_content_version: self.hub_content_version,
        })
    }
}
