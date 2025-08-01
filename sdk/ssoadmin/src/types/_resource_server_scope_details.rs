// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that describes details for an IAM Identity Center access scope that is associated with a resource server.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceServerScopeDetails {
    /// <p>The description of an access scope for a resource server.</p>
    pub long_description: ::std::option::Option<::std::string::String>,
    /// <p>The title of an access scope for a resource server.</p>
    pub detailed_title: ::std::option::Option<::std::string::String>,
}
impl ResourceServerScopeDetails {
    /// <p>The description of an access scope for a resource server.</p>
    pub fn long_description(&self) -> ::std::option::Option<&str> {
        self.long_description.as_deref()
    }
    /// <p>The title of an access scope for a resource server.</p>
    pub fn detailed_title(&self) -> ::std::option::Option<&str> {
        self.detailed_title.as_deref()
    }
}
impl ResourceServerScopeDetails {
    /// Creates a new builder-style object to manufacture [`ResourceServerScopeDetails`](crate::types::ResourceServerScopeDetails).
    pub fn builder() -> crate::types::builders::ResourceServerScopeDetailsBuilder {
        crate::types::builders::ResourceServerScopeDetailsBuilder::default()
    }
}

/// A builder for [`ResourceServerScopeDetails`](crate::types::ResourceServerScopeDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceServerScopeDetailsBuilder {
    pub(crate) long_description: ::std::option::Option<::std::string::String>,
    pub(crate) detailed_title: ::std::option::Option<::std::string::String>,
}
impl ResourceServerScopeDetailsBuilder {
    /// <p>The description of an access scope for a resource server.</p>
    pub fn long_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.long_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of an access scope for a resource server.</p>
    pub fn set_long_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.long_description = input;
        self
    }
    /// <p>The description of an access scope for a resource server.</p>
    pub fn get_long_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.long_description
    }
    /// <p>The title of an access scope for a resource server.</p>
    pub fn detailed_title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detailed_title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of an access scope for a resource server.</p>
    pub fn set_detailed_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detailed_title = input;
        self
    }
    /// <p>The title of an access scope for a resource server.</p>
    pub fn get_detailed_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.detailed_title
    }
    /// Consumes the builder and constructs a [`ResourceServerScopeDetails`](crate::types::ResourceServerScopeDetails).
    pub fn build(self) -> crate::types::ResourceServerScopeDetails {
        crate::types::ResourceServerScopeDetails {
            long_description: self.long_description,
            detailed_title: self.detailed_title,
        }
    }
}
