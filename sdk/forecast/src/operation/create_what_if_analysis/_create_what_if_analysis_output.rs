// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWhatIfAnalysisOutput {
    /// <p>The Amazon Resource Name (ARN) of the what-if analysis.</p>
    pub what_if_analysis_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateWhatIfAnalysisOutput {
    /// <p>The Amazon Resource Name (ARN) of the what-if analysis.</p>
    pub fn what_if_analysis_arn(&self) -> ::std::option::Option<&str> {
        self.what_if_analysis_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateWhatIfAnalysisOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateWhatIfAnalysisOutput {
    /// Creates a new builder-style object to manufacture [`CreateWhatIfAnalysisOutput`](crate::operation::create_what_if_analysis::CreateWhatIfAnalysisOutput).
    pub fn builder() -> crate::operation::create_what_if_analysis::builders::CreateWhatIfAnalysisOutputBuilder {
        crate::operation::create_what_if_analysis::builders::CreateWhatIfAnalysisOutputBuilder::default()
    }
}

/// A builder for [`CreateWhatIfAnalysisOutput`](crate::operation::create_what_if_analysis::CreateWhatIfAnalysisOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWhatIfAnalysisOutputBuilder {
    pub(crate) what_if_analysis_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateWhatIfAnalysisOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the what-if analysis.</p>
    pub fn what_if_analysis_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.what_if_analysis_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the what-if analysis.</p>
    pub fn set_what_if_analysis_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.what_if_analysis_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the what-if analysis.</p>
    pub fn get_what_if_analysis_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.what_if_analysis_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateWhatIfAnalysisOutput`](crate::operation::create_what_if_analysis::CreateWhatIfAnalysisOutput).
    pub fn build(self) -> crate::operation::create_what_if_analysis::CreateWhatIfAnalysisOutput {
        crate::operation::create_what_if_analysis::CreateWhatIfAnalysisOutput {
            what_if_analysis_arn: self.what_if_analysis_arn,
            _request_id: self._request_id,
        }
    }
}
