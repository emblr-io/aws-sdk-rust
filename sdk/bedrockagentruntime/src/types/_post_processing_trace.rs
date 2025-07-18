// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the post-processing step, in which the agent shapes the response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum PostProcessingTrace {
    /// <p>The input for the post-processing step.</p>
    /// <ul>
    /// <li>
    /// <p>The <code>type</code> is <code>POST_PROCESSING</code>.</p></li>
    /// <li>
    /// <p>The <code>text</code> contains the prompt.</p></li>
    /// <li>
    /// <p>The <code>inferenceConfiguration</code>, <code>parserMode</code>, and <code>overrideLambda</code> values are set in the <a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_PromptOverrideConfiguration.html">PromptOverrideConfiguration</a> object that was set when the agent was created or updated.</p></li>
    /// </ul>
    ModelInvocationInput(crate::types::ModelInvocationInput),
    /// <p>The foundation model output from the post-processing step.</p>
    ModelInvocationOutput(crate::types::PostProcessingModelInvocationOutput),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl PostProcessingTrace {
    /// Tries to convert the enum instance into [`ModelInvocationInput`](crate::types::PostProcessingTrace::ModelInvocationInput), extracting the inner [`ModelInvocationInput`](crate::types::ModelInvocationInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_model_invocation_input(&self) -> ::std::result::Result<&crate::types::ModelInvocationInput, &Self> {
        if let PostProcessingTrace::ModelInvocationInput(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ModelInvocationInput`](crate::types::PostProcessingTrace::ModelInvocationInput).
    pub fn is_model_invocation_input(&self) -> bool {
        self.as_model_invocation_input().is_ok()
    }
    /// Tries to convert the enum instance into [`ModelInvocationOutput`](crate::types::PostProcessingTrace::ModelInvocationOutput), extracting the inner [`PostProcessingModelInvocationOutput`](crate::types::PostProcessingModelInvocationOutput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_model_invocation_output(&self) -> ::std::result::Result<&crate::types::PostProcessingModelInvocationOutput, &Self> {
        if let PostProcessingTrace::ModelInvocationOutput(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ModelInvocationOutput`](crate::types::PostProcessingTrace::ModelInvocationOutput).
    pub fn is_model_invocation_output(&self) -> bool {
        self.as_model_invocation_output().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for PostProcessingTrace {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::std::write!(f, "*** Sensitive Data Redacted ***")
    }
}
