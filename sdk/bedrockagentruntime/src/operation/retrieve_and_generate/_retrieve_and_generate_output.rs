// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct RetrieveAndGenerateOutput {
    /// <p>The unique identifier of the session. When you first make a <code>RetrieveAndGenerate</code> request, Amazon Bedrock automatically generates this value. You must reuse this value for all subsequent requests in the same conversational session. This value allows Amazon Bedrock to maintain context and knowledge from previous interactions. You can't explicitly set the <code>sessionId</code> yourself.</p>
    pub session_id: ::std::string::String,
    /// <p>Contains the response generated from querying the knowledge base.</p>
    pub output: ::std::option::Option<crate::types::RetrieveAndGenerateOutput>,
    /// <p>A list of segments of the generated response that are based on sources in the knowledge base, alongside information about the sources.</p>
    pub citations: ::std::option::Option<::std::vec::Vec<crate::types::Citation>>,
    /// <p>Specifies if there is a guardrail intervention in the response.</p>
    pub guardrail_action: ::std::option::Option<crate::types::GuadrailAction>,
    _request_id: Option<String>,
}
impl RetrieveAndGenerateOutput {
    /// <p>The unique identifier of the session. When you first make a <code>RetrieveAndGenerate</code> request, Amazon Bedrock automatically generates this value. You must reuse this value for all subsequent requests in the same conversational session. This value allows Amazon Bedrock to maintain context and knowledge from previous interactions. You can't explicitly set the <code>sessionId</code> yourself.</p>
    pub fn session_id(&self) -> &str {
        use std::ops::Deref;
        self.session_id.deref()
    }
    /// <p>Contains the response generated from querying the knowledge base.</p>
    pub fn output(&self) -> ::std::option::Option<&crate::types::RetrieveAndGenerateOutput> {
        self.output.as_ref()
    }
    /// <p>A list of segments of the generated response that are based on sources in the knowledge base, alongside information about the sources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.citations.is_none()`.
    pub fn citations(&self) -> &[crate::types::Citation] {
        self.citations.as_deref().unwrap_or_default()
    }
    /// <p>Specifies if there is a guardrail intervention in the response.</p>
    pub fn guardrail_action(&self) -> ::std::option::Option<&crate::types::GuadrailAction> {
        self.guardrail_action.as_ref()
    }
}
impl ::std::fmt::Debug for RetrieveAndGenerateOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RetrieveAndGenerateOutput");
        formatter.field("session_id", &self.session_id);
        formatter.field("output", &"*** Sensitive Data Redacted ***");
        formatter.field("citations", &self.citations);
        formatter.field("guardrail_action", &self.guardrail_action);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for RetrieveAndGenerateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RetrieveAndGenerateOutput {
    /// Creates a new builder-style object to manufacture [`RetrieveAndGenerateOutput`](crate::operation::retrieve_and_generate::RetrieveAndGenerateOutput).
    pub fn builder() -> crate::operation::retrieve_and_generate::builders::RetrieveAndGenerateOutputBuilder {
        crate::operation::retrieve_and_generate::builders::RetrieveAndGenerateOutputBuilder::default()
    }
}

/// A builder for [`RetrieveAndGenerateOutput`](crate::operation::retrieve_and_generate::RetrieveAndGenerateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RetrieveAndGenerateOutputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) output: ::std::option::Option<crate::types::RetrieveAndGenerateOutput>,
    pub(crate) citations: ::std::option::Option<::std::vec::Vec<crate::types::Citation>>,
    pub(crate) guardrail_action: ::std::option::Option<crate::types::GuadrailAction>,
    _request_id: Option<String>,
}
impl RetrieveAndGenerateOutputBuilder {
    /// <p>The unique identifier of the session. When you first make a <code>RetrieveAndGenerate</code> request, Amazon Bedrock automatically generates this value. You must reuse this value for all subsequent requests in the same conversational session. This value allows Amazon Bedrock to maintain context and knowledge from previous interactions. You can't explicitly set the <code>sessionId</code> yourself.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the session. When you first make a <code>RetrieveAndGenerate</code> request, Amazon Bedrock automatically generates this value. You must reuse this value for all subsequent requests in the same conversational session. This value allows Amazon Bedrock to maintain context and knowledge from previous interactions. You can't explicitly set the <code>sessionId</code> yourself.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The unique identifier of the session. When you first make a <code>RetrieveAndGenerate</code> request, Amazon Bedrock automatically generates this value. You must reuse this value for all subsequent requests in the same conversational session. This value allows Amazon Bedrock to maintain context and knowledge from previous interactions. You can't explicitly set the <code>sessionId</code> yourself.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>Contains the response generated from querying the knowledge base.</p>
    /// This field is required.
    pub fn output(mut self, input: crate::types::RetrieveAndGenerateOutput) -> Self {
        self.output = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the response generated from querying the knowledge base.</p>
    pub fn set_output(mut self, input: ::std::option::Option<crate::types::RetrieveAndGenerateOutput>) -> Self {
        self.output = input;
        self
    }
    /// <p>Contains the response generated from querying the knowledge base.</p>
    pub fn get_output(&self) -> &::std::option::Option<crate::types::RetrieveAndGenerateOutput> {
        &self.output
    }
    /// Appends an item to `citations`.
    ///
    /// To override the contents of this collection use [`set_citations`](Self::set_citations).
    ///
    /// <p>A list of segments of the generated response that are based on sources in the knowledge base, alongside information about the sources.</p>
    pub fn citations(mut self, input: crate::types::Citation) -> Self {
        let mut v = self.citations.unwrap_or_default();
        v.push(input);
        self.citations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of segments of the generated response that are based on sources in the knowledge base, alongside information about the sources.</p>
    pub fn set_citations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Citation>>) -> Self {
        self.citations = input;
        self
    }
    /// <p>A list of segments of the generated response that are based on sources in the knowledge base, alongside information about the sources.</p>
    pub fn get_citations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Citation>> {
        &self.citations
    }
    /// <p>Specifies if there is a guardrail intervention in the response.</p>
    pub fn guardrail_action(mut self, input: crate::types::GuadrailAction) -> Self {
        self.guardrail_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if there is a guardrail intervention in the response.</p>
    pub fn set_guardrail_action(mut self, input: ::std::option::Option<crate::types::GuadrailAction>) -> Self {
        self.guardrail_action = input;
        self
    }
    /// <p>Specifies if there is a guardrail intervention in the response.</p>
    pub fn get_guardrail_action(&self) -> &::std::option::Option<crate::types::GuadrailAction> {
        &self.guardrail_action
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RetrieveAndGenerateOutput`](crate::operation::retrieve_and_generate::RetrieveAndGenerateOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`session_id`](crate::operation::retrieve_and_generate::builders::RetrieveAndGenerateOutputBuilder::session_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::retrieve_and_generate::RetrieveAndGenerateOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::retrieve_and_generate::RetrieveAndGenerateOutput {
            session_id: self.session_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_id",
                    "session_id was not specified but it is required when building RetrieveAndGenerateOutput",
                )
            })?,
            output: self.output,
            citations: self.citations,
            guardrail_action: self.guardrail_action,
            _request_id: self._request_id,
        })
    }
}
impl ::std::fmt::Debug for RetrieveAndGenerateOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RetrieveAndGenerateOutputBuilder");
        formatter.field("session_id", &self.session_id);
        formatter.field("output", &"*** Sensitive Data Redacted ***");
        formatter.field("citations", &self.citations);
        formatter.field("guardrail_action", &self.guardrail_action);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
