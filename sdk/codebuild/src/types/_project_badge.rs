// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the build badge for the build project.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProjectBadge {
    /// <p>Set this to true to generate a publicly accessible URL for your project's build badge.</p>
    pub badge_enabled: bool,
    /// <p>The publicly-accessible URL through which you can access the build badge for your project.</p>
    pub badge_request_url: ::std::option::Option<::std::string::String>,
}
impl ProjectBadge {
    /// <p>Set this to true to generate a publicly accessible URL for your project's build badge.</p>
    pub fn badge_enabled(&self) -> bool {
        self.badge_enabled
    }
    /// <p>The publicly-accessible URL through which you can access the build badge for your project.</p>
    pub fn badge_request_url(&self) -> ::std::option::Option<&str> {
        self.badge_request_url.as_deref()
    }
}
impl ProjectBadge {
    /// Creates a new builder-style object to manufacture [`ProjectBadge`](crate::types::ProjectBadge).
    pub fn builder() -> crate::types::builders::ProjectBadgeBuilder {
        crate::types::builders::ProjectBadgeBuilder::default()
    }
}

/// A builder for [`ProjectBadge`](crate::types::ProjectBadge).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProjectBadgeBuilder {
    pub(crate) badge_enabled: ::std::option::Option<bool>,
    pub(crate) badge_request_url: ::std::option::Option<::std::string::String>,
}
impl ProjectBadgeBuilder {
    /// <p>Set this to true to generate a publicly accessible URL for your project's build badge.</p>
    pub fn badge_enabled(mut self, input: bool) -> Self {
        self.badge_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set this to true to generate a publicly accessible URL for your project's build badge.</p>
    pub fn set_badge_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.badge_enabled = input;
        self
    }
    /// <p>Set this to true to generate a publicly accessible URL for your project's build badge.</p>
    pub fn get_badge_enabled(&self) -> &::std::option::Option<bool> {
        &self.badge_enabled
    }
    /// <p>The publicly-accessible URL through which you can access the build badge for your project.</p>
    pub fn badge_request_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.badge_request_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The publicly-accessible URL through which you can access the build badge for your project.</p>
    pub fn set_badge_request_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.badge_request_url = input;
        self
    }
    /// <p>The publicly-accessible URL through which you can access the build badge for your project.</p>
    pub fn get_badge_request_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.badge_request_url
    }
    /// Consumes the builder and constructs a [`ProjectBadge`](crate::types::ProjectBadge).
    pub fn build(self) -> crate::types::ProjectBadge {
        crate::types::ProjectBadge {
            badge_enabled: self.badge_enabled.unwrap_or_default(),
            badge_request_url: self.badge_request_url,
        }
    }
}
