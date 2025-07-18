// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The tier that your guardrail uses for denied topic filters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GuardrailTopicsTier {
    /// <p>The tier that your guardrail uses for denied topic filters. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLASSIC</code> tier – Provides established guardrails functionality supporting English, French, and Spanish languages.</p></li>
    /// <li>
    /// <p><code>STANDARD</code> tier – Provides a more robust solution than the <code>CLASSIC</code> tier and has more comprehensive language support. This tier requires that your guardrail use <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region.html">cross-Region inference</a>.</p></li>
    /// </ul>
    pub tier_name: crate::types::GuardrailTopicsTierName,
}
impl GuardrailTopicsTier {
    /// <p>The tier that your guardrail uses for denied topic filters. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLASSIC</code> tier – Provides established guardrails functionality supporting English, French, and Spanish languages.</p></li>
    /// <li>
    /// <p><code>STANDARD</code> tier – Provides a more robust solution than the <code>CLASSIC</code> tier and has more comprehensive language support. This tier requires that your guardrail use <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region.html">cross-Region inference</a>.</p></li>
    /// </ul>
    pub fn tier_name(&self) -> &crate::types::GuardrailTopicsTierName {
        &self.tier_name
    }
}
impl ::std::fmt::Debug for GuardrailTopicsTier {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GuardrailTopicsTier");
        formatter.field("tier_name", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl GuardrailTopicsTier {
    /// Creates a new builder-style object to manufacture [`GuardrailTopicsTier`](crate::types::GuardrailTopicsTier).
    pub fn builder() -> crate::types::builders::GuardrailTopicsTierBuilder {
        crate::types::builders::GuardrailTopicsTierBuilder::default()
    }
}

/// A builder for [`GuardrailTopicsTier`](crate::types::GuardrailTopicsTier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GuardrailTopicsTierBuilder {
    pub(crate) tier_name: ::std::option::Option<crate::types::GuardrailTopicsTierName>,
}
impl GuardrailTopicsTierBuilder {
    /// <p>The tier that your guardrail uses for denied topic filters. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLASSIC</code> tier – Provides established guardrails functionality supporting English, French, and Spanish languages.</p></li>
    /// <li>
    /// <p><code>STANDARD</code> tier – Provides a more robust solution than the <code>CLASSIC</code> tier and has more comprehensive language support. This tier requires that your guardrail use <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region.html">cross-Region inference</a>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn tier_name(mut self, input: crate::types::GuardrailTopicsTierName) -> Self {
        self.tier_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tier that your guardrail uses for denied topic filters. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLASSIC</code> tier – Provides established guardrails functionality supporting English, French, and Spanish languages.</p></li>
    /// <li>
    /// <p><code>STANDARD</code> tier – Provides a more robust solution than the <code>CLASSIC</code> tier and has more comprehensive language support. This tier requires that your guardrail use <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region.html">cross-Region inference</a>.</p></li>
    /// </ul>
    pub fn set_tier_name(mut self, input: ::std::option::Option<crate::types::GuardrailTopicsTierName>) -> Self {
        self.tier_name = input;
        self
    }
    /// <p>The tier that your guardrail uses for denied topic filters. Valid values include:</p>
    /// <ul>
    /// <li>
    /// <p><code>CLASSIC</code> tier – Provides established guardrails functionality supporting English, French, and Spanish languages.</p></li>
    /// <li>
    /// <p><code>STANDARD</code> tier – Provides a more robust solution than the <code>CLASSIC</code> tier and has more comprehensive language support. This tier requires that your guardrail use <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region.html">cross-Region inference</a>.</p></li>
    /// </ul>
    pub fn get_tier_name(&self) -> &::std::option::Option<crate::types::GuardrailTopicsTierName> {
        &self.tier_name
    }
    /// Consumes the builder and constructs a [`GuardrailTopicsTier`](crate::types::GuardrailTopicsTier).
    /// This method will fail if any of the following fields are not set:
    /// - [`tier_name`](crate::types::builders::GuardrailTopicsTierBuilder::tier_name)
    pub fn build(self) -> ::std::result::Result<crate::types::GuardrailTopicsTier, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GuardrailTopicsTier {
            tier_name: self.tier_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tier_name",
                    "tier_name was not specified but it is required when building GuardrailTopicsTier",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for GuardrailTopicsTierBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GuardrailTopicsTierBuilder");
        formatter.field("tier_name", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
