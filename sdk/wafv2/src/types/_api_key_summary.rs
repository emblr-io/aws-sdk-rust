// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information for a single API key.</p>
/// <p>API keys are required for the integration of the CAPTCHA API in your JavaScript client applications. The API lets you customize the placement and characteristics of the CAPTCHA puzzle for your end users. For more information about the CAPTCHA JavaScript integration, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-integration.html">WAF client application integration</a> in the <i>WAF Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApiKeySummary {
    /// <p>The token domains that are defined in this API key.</p>
    pub token_domains: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The generated, encrypted API key. You can copy this for use in your JavaScript CAPTCHA integration.</p>
    pub api_key: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the key was created.</p>
    pub creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Internal value used by WAF to manage the key.</p>
    pub version: i32,
}
impl ApiKeySummary {
    /// <p>The token domains that are defined in this API key.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.token_domains.is_none()`.
    pub fn token_domains(&self) -> &[::std::string::String] {
        self.token_domains.as_deref().unwrap_or_default()
    }
    /// <p>The generated, encrypted API key. You can copy this for use in your JavaScript CAPTCHA integration.</p>
    pub fn api_key(&self) -> ::std::option::Option<&str> {
        self.api_key.as_deref()
    }
    /// <p>The date and time that the key was created.</p>
    pub fn creation_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_timestamp.as_ref()
    }
    /// <p>Internal value used by WAF to manage the key.</p>
    pub fn version(&self) -> i32 {
        self.version
    }
}
impl ApiKeySummary {
    /// Creates a new builder-style object to manufacture [`ApiKeySummary`](crate::types::ApiKeySummary).
    pub fn builder() -> crate::types::builders::ApiKeySummaryBuilder {
        crate::types::builders::ApiKeySummaryBuilder::default()
    }
}

/// A builder for [`ApiKeySummary`](crate::types::ApiKeySummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApiKeySummaryBuilder {
    pub(crate) token_domains: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) api_key: ::std::option::Option<::std::string::String>,
    pub(crate) creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) version: ::std::option::Option<i32>,
}
impl ApiKeySummaryBuilder {
    /// Appends an item to `token_domains`.
    ///
    /// To override the contents of this collection use [`set_token_domains`](Self::set_token_domains).
    ///
    /// <p>The token domains that are defined in this API key.</p>
    pub fn token_domains(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.token_domains.unwrap_or_default();
        v.push(input.into());
        self.token_domains = ::std::option::Option::Some(v);
        self
    }
    /// <p>The token domains that are defined in this API key.</p>
    pub fn set_token_domains(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.token_domains = input;
        self
    }
    /// <p>The token domains that are defined in this API key.</p>
    pub fn get_token_domains(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.token_domains
    }
    /// <p>The generated, encrypted API key. You can copy this for use in your JavaScript CAPTCHA integration.</p>
    pub fn api_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The generated, encrypted API key. You can copy this for use in your JavaScript CAPTCHA integration.</p>
    pub fn set_api_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_key = input;
        self
    }
    /// <p>The generated, encrypted API key. You can copy this for use in your JavaScript CAPTCHA integration.</p>
    pub fn get_api_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_key
    }
    /// <p>The date and time that the key was created.</p>
    pub fn creation_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the key was created.</p>
    pub fn set_creation_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_timestamp = input;
        self
    }
    /// <p>The date and time that the key was created.</p>
    pub fn get_creation_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_timestamp
    }
    /// <p>Internal value used by WAF to manage the key.</p>
    pub fn version(mut self, input: i32) -> Self {
        self.version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Internal value used by WAF to manage the key.</p>
    pub fn set_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version = input;
        self
    }
    /// <p>Internal value used by WAF to manage the key.</p>
    pub fn get_version(&self) -> &::std::option::Option<i32> {
        &self.version
    }
    /// Consumes the builder and constructs a [`ApiKeySummary`](crate::types::ApiKeySummary).
    pub fn build(self) -> crate::types::ApiKeySummary {
        crate::types::ApiKeySummary {
            token_domains: self.token_domains,
            api_key: self.api_key,
            creation_timestamp: self.creation_timestamp,
            version: self.version.unwrap_or_default(),
        }
    }
}
