// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The API request rate limits.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ThrottleSettings {
    /// <p>The API target request burst rate limit. This allows more requests through for a period of time than the target rate limit.</p>
    pub burst_limit: i32,
    /// <p>The API target request rate limit.</p>
    pub rate_limit: f64,
}
impl ThrottleSettings {
    /// <p>The API target request burst rate limit. This allows more requests through for a period of time than the target rate limit.</p>
    pub fn burst_limit(&self) -> i32 {
        self.burst_limit
    }
    /// <p>The API target request rate limit.</p>
    pub fn rate_limit(&self) -> f64 {
        self.rate_limit
    }
}
impl ThrottleSettings {
    /// Creates a new builder-style object to manufacture [`ThrottleSettings`](crate::types::ThrottleSettings).
    pub fn builder() -> crate::types::builders::ThrottleSettingsBuilder {
        crate::types::builders::ThrottleSettingsBuilder::default()
    }
}

/// A builder for [`ThrottleSettings`](crate::types::ThrottleSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ThrottleSettingsBuilder {
    pub(crate) burst_limit: ::std::option::Option<i32>,
    pub(crate) rate_limit: ::std::option::Option<f64>,
}
impl ThrottleSettingsBuilder {
    /// <p>The API target request burst rate limit. This allows more requests through for a period of time than the target rate limit.</p>
    pub fn burst_limit(mut self, input: i32) -> Self {
        self.burst_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The API target request burst rate limit. This allows more requests through for a period of time than the target rate limit.</p>
    pub fn set_burst_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.burst_limit = input;
        self
    }
    /// <p>The API target request burst rate limit. This allows more requests through for a period of time than the target rate limit.</p>
    pub fn get_burst_limit(&self) -> &::std::option::Option<i32> {
        &self.burst_limit
    }
    /// <p>The API target request rate limit.</p>
    pub fn rate_limit(mut self, input: f64) -> Self {
        self.rate_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The API target request rate limit.</p>
    pub fn set_rate_limit(mut self, input: ::std::option::Option<f64>) -> Self {
        self.rate_limit = input;
        self
    }
    /// <p>The API target request rate limit.</p>
    pub fn get_rate_limit(&self) -> &::std::option::Option<f64> {
        &self.rate_limit
    }
    /// Consumes the builder and constructs a [`ThrottleSettings`](crate::types::ThrottleSettings).
    pub fn build(self) -> crate::types::ThrottleSettings {
        crate::types::ThrottleSettings {
            burst_limit: self.burst_limit.unwrap_or_default(),
            rate_limit: self.rate_limit.unwrap_or_default(),
        }
    }
}
