// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use this processor to parse WAF vended logs, extract fields, and and convert them into a JSON format. This processor always processes the entire log event message. For more information about this processor including examples, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Transformation.html#CloudWatch-Logs-Transformation-parsePostGres"> parseWAF</a>.</p>
/// <p>For more information about WAF log format, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/logging-examples.html"> Log examples for web ACL traffic</a>.</p><important>
/// <p>If you use this processor, it must be the first processor in your transformer.</p>
/// </important>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParseWaf {
    /// <p>Omit this parameter and the whole log message will be processed by this processor. No other value than <code>@message</code> is allowed for <code>source</code>.</p>
    pub source: ::std::option::Option<::std::string::String>,
}
impl ParseWaf {
    /// <p>Omit this parameter and the whole log message will be processed by this processor. No other value than <code>@message</code> is allowed for <code>source</code>.</p>
    pub fn source(&self) -> ::std::option::Option<&str> {
        self.source.as_deref()
    }
}
impl ParseWaf {
    /// Creates a new builder-style object to manufacture [`ParseWaf`](crate::types::ParseWaf).
    pub fn builder() -> crate::types::builders::ParseWafBuilder {
        crate::types::builders::ParseWafBuilder::default()
    }
}

/// A builder for [`ParseWaf`](crate::types::ParseWaf).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParseWafBuilder {
    pub(crate) source: ::std::option::Option<::std::string::String>,
}
impl ParseWafBuilder {
    /// <p>Omit this parameter and the whole log message will be processed by this processor. No other value than <code>@message</code> is allowed for <code>source</code>.</p>
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Omit this parameter and the whole log message will be processed by this processor. No other value than <code>@message</code> is allowed for <code>source</code>.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>Omit this parameter and the whole log message will be processed by this processor. No other value than <code>@message</code> is allowed for <code>source</code>.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// Consumes the builder and constructs a [`ParseWaf`](crate::types::ParseWaf).
    pub fn build(self) -> crate::types::ParseWaf {
        crate::types::ParseWaf { source: self.source }
    }
}
