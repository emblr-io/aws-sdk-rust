// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a request to create or edit the <code>StopInstanceOnIdle</code> add-on.</p><important>
/// <p>This add-on only applies to Lightsail for Research resources.</p>
/// </important>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopInstanceOnIdleRequest {
    /// <p>The value to compare with the duration.</p>
    pub threshold: ::std::option::Option<::std::string::String>,
    /// <p>The amount of idle time in minutes after which your virtual computer will automatically stop.</p>
    pub duration: ::std::option::Option<::std::string::String>,
}
impl StopInstanceOnIdleRequest {
    /// <p>The value to compare with the duration.</p>
    pub fn threshold(&self) -> ::std::option::Option<&str> {
        self.threshold.as_deref()
    }
    /// <p>The amount of idle time in minutes after which your virtual computer will automatically stop.</p>
    pub fn duration(&self) -> ::std::option::Option<&str> {
        self.duration.as_deref()
    }
}
impl StopInstanceOnIdleRequest {
    /// Creates a new builder-style object to manufacture [`StopInstanceOnIdleRequest`](crate::types::StopInstanceOnIdleRequest).
    pub fn builder() -> crate::types::builders::StopInstanceOnIdleRequestBuilder {
        crate::types::builders::StopInstanceOnIdleRequestBuilder::default()
    }
}

/// A builder for [`StopInstanceOnIdleRequest`](crate::types::StopInstanceOnIdleRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopInstanceOnIdleRequestBuilder {
    pub(crate) threshold: ::std::option::Option<::std::string::String>,
    pub(crate) duration: ::std::option::Option<::std::string::String>,
}
impl StopInstanceOnIdleRequestBuilder {
    /// <p>The value to compare with the duration.</p>
    pub fn threshold(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.threshold = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value to compare with the duration.</p>
    pub fn set_threshold(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.threshold = input;
        self
    }
    /// <p>The value to compare with the duration.</p>
    pub fn get_threshold(&self) -> &::std::option::Option<::std::string::String> {
        &self.threshold
    }
    /// <p>The amount of idle time in minutes after which your virtual computer will automatically stop.</p>
    pub fn duration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.duration = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The amount of idle time in minutes after which your virtual computer will automatically stop.</p>
    pub fn set_duration(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.duration = input;
        self
    }
    /// <p>The amount of idle time in minutes after which your virtual computer will automatically stop.</p>
    pub fn get_duration(&self) -> &::std::option::Option<::std::string::String> {
        &self.duration
    }
    /// Consumes the builder and constructs a [`StopInstanceOnIdleRequest`](crate::types::StopInstanceOnIdleRequest).
    pub fn build(self) -> crate::types::StopInstanceOnIdleRequest {
        crate::types::StopInstanceOnIdleRequest {
            threshold: self.threshold,
            duration: self.duration,
        }
    }
}
