// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The resource in a list of resources.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourcesListItem {
    /// <p>The Amazon resource name (ARN) of the resource.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The message returned if the call fails.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>The status of the list item.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>Provides information about the AppRegistry resource type.</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
}
impl ResourcesListItem {
    /// <p>The Amazon resource name (ARN) of the resource.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The message returned if the call fails.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>The status of the list item.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>Provides information about the AppRegistry resource type.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
}
impl ResourcesListItem {
    /// Creates a new builder-style object to manufacture [`ResourcesListItem`](crate::types::ResourcesListItem).
    pub fn builder() -> crate::types::builders::ResourcesListItemBuilder {
        crate::types::builders::ResourcesListItemBuilder::default()
    }
}

/// A builder for [`ResourcesListItem`](crate::types::ResourcesListItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourcesListItemBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
}
impl ResourcesListItemBuilder {
    /// <p>The Amazon resource name (ARN) of the resource.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon resource name (ARN) of the resource.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon resource name (ARN) of the resource.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The message returned if the call fails.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message returned if the call fails.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The message returned if the call fails.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>The status of the list item.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the list item.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the list item.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>Provides information about the AppRegistry resource type.</p>
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides information about the AppRegistry resource type.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>Provides information about the AppRegistry resource type.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// Consumes the builder and constructs a [`ResourcesListItem`](crate::types::ResourcesListItem).
    pub fn build(self) -> crate::types::ResourcesListItem {
        crate::types::ResourcesListItem {
            resource_arn: self.resource_arn,
            error_message: self.error_message,
            status: self.status,
            resource_type: self.resource_type,
        }
    }
}
