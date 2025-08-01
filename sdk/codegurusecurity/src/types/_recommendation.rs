// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the recommended course of action to remediate a finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Recommendation {
    /// <p>The recommended course of action to remediate the finding.</p>
    pub text: ::std::option::Option<::std::string::String>,
    /// <p>The URL address to the recommendation for remediating the finding.</p>
    pub url: ::std::option::Option<::std::string::String>,
}
impl Recommendation {
    /// <p>The recommended course of action to remediate the finding.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
    /// <p>The URL address to the recommendation for remediating the finding.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl Recommendation {
    /// Creates a new builder-style object to manufacture [`Recommendation`](crate::types::Recommendation).
    pub fn builder() -> crate::types::builders::RecommendationBuilder {
        crate::types::builders::RecommendationBuilder::default()
    }
}

/// A builder for [`Recommendation`](crate::types::Recommendation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecommendationBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl RecommendationBuilder {
    /// <p>The recommended course of action to remediate the finding.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The recommended course of action to remediate the finding.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The recommended course of action to remediate the finding.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// <p>The URL address to the recommendation for remediating the finding.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL address to the recommendation for remediating the finding.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>The URL address to the recommendation for remediating the finding.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`Recommendation`](crate::types::Recommendation).
    pub fn build(self) -> crate::types::Recommendation {
        crate::types::Recommendation {
            text: self.text,
            url: self.url,
        }
    }
}
