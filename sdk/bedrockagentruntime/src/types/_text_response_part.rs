// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the part of the generated text that contains a citation, alongside where it begins and ends.</p>
/// <p>This data type is used in the following API operations:</p>
/// <ul>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_RetrieveAndGenerate.html#API_agent-runtime_RetrieveAndGenerate_ResponseSyntax">RetrieveAndGenerate response</a> – in the <code>textResponsePart</code> field</p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html#API_agent-runtime_InvokeAgent_ResponseSyntax">InvokeAgent response</a> – in the <code>textResponsePart</code> field</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct TextResponsePart {
    /// <p>The part of the generated text that contains a citation.</p>
    pub text: ::std::option::Option<::std::string::String>,
    /// <p>Contains information about where the text with a citation begins and ends in the generated output.</p>
    pub span: ::std::option::Option<crate::types::Span>,
}
impl TextResponsePart {
    /// <p>The part of the generated text that contains a citation.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
    /// <p>Contains information about where the text with a citation begins and ends in the generated output.</p>
    pub fn span(&self) -> ::std::option::Option<&crate::types::Span> {
        self.span.as_ref()
    }
}
impl ::std::fmt::Debug for TextResponsePart {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TextResponsePart");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("span", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl TextResponsePart {
    /// Creates a new builder-style object to manufacture [`TextResponsePart`](crate::types::TextResponsePart).
    pub fn builder() -> crate::types::builders::TextResponsePartBuilder {
        crate::types::builders::TextResponsePartBuilder::default()
    }
}

/// A builder for [`TextResponsePart`](crate::types::TextResponsePart).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct TextResponsePartBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) span: ::std::option::Option<crate::types::Span>,
}
impl TextResponsePartBuilder {
    /// <p>The part of the generated text that contains a citation.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The part of the generated text that contains a citation.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The part of the generated text that contains a citation.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// <p>Contains information about where the text with a citation begins and ends in the generated output.</p>
    pub fn span(mut self, input: crate::types::Span) -> Self {
        self.span = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about where the text with a citation begins and ends in the generated output.</p>
    pub fn set_span(mut self, input: ::std::option::Option<crate::types::Span>) -> Self {
        self.span = input;
        self
    }
    /// <p>Contains information about where the text with a citation begins and ends in the generated output.</p>
    pub fn get_span(&self) -> &::std::option::Option<crate::types::Span> {
        &self.span
    }
    /// Consumes the builder and constructs a [`TextResponsePart`](crate::types::TextResponsePart).
    pub fn build(self) -> crate::types::TextResponsePart {
        crate::types::TextResponsePart {
            text: self.text,
            span: self.span,
        }
    }
}
impl ::std::fmt::Debug for TextResponsePartBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TextResponsePartBuilder");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.field("span", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
