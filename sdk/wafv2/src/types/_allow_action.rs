// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies that WAF should allow the request and optionally defines additional custom handling for the request.</p>
/// <p>This is used in the context of other settings, for example to specify values for <code>RuleAction</code> and web ACL <code>DefaultAction</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AllowAction {
    /// <p>Defines custom handling for the web request.</p>
    /// <p>For information about customizing web requests and responses, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html">Customizing web requests and responses in WAF</a> in the <i>WAF Developer Guide</i>.</p>
    pub custom_request_handling: ::std::option::Option<crate::types::CustomRequestHandling>,
}
impl AllowAction {
    /// <p>Defines custom handling for the web request.</p>
    /// <p>For information about customizing web requests and responses, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html">Customizing web requests and responses in WAF</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn custom_request_handling(&self) -> ::std::option::Option<&crate::types::CustomRequestHandling> {
        self.custom_request_handling.as_ref()
    }
}
impl AllowAction {
    /// Creates a new builder-style object to manufacture [`AllowAction`](crate::types::AllowAction).
    pub fn builder() -> crate::types::builders::AllowActionBuilder {
        crate::types::builders::AllowActionBuilder::default()
    }
}

/// A builder for [`AllowAction`](crate::types::AllowAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AllowActionBuilder {
    pub(crate) custom_request_handling: ::std::option::Option<crate::types::CustomRequestHandling>,
}
impl AllowActionBuilder {
    /// <p>Defines custom handling for the web request.</p>
    /// <p>For information about customizing web requests and responses, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html">Customizing web requests and responses in WAF</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn custom_request_handling(mut self, input: crate::types::CustomRequestHandling) -> Self {
        self.custom_request_handling = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines custom handling for the web request.</p>
    /// <p>For information about customizing web requests and responses, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html">Customizing web requests and responses in WAF</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn set_custom_request_handling(mut self, input: ::std::option::Option<crate::types::CustomRequestHandling>) -> Self {
        self.custom_request_handling = input;
        self
    }
    /// <p>Defines custom handling for the web request.</p>
    /// <p>For information about customizing web requests and responses, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-custom-request-response.html">Customizing web requests and responses in WAF</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn get_custom_request_handling(&self) -> &::std::option::Option<crate::types::CustomRequestHandling> {
        &self.custom_request_handling
    }
    /// Consumes the builder and constructs a [`AllowAction`](crate::types::AllowAction).
    pub fn build(self) -> crate::types::AllowAction {
        crate::types::AllowAction {
            custom_request_handling: self.custom_request_handling,
        }
    }
}
