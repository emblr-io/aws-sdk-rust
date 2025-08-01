// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePredictorBacktestExportJobOutput {
    /// <p>The Amazon Resource Name (ARN) of the predictor backtest export job that you want to export.</p>
    pub predictor_backtest_export_job_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePredictorBacktestExportJobOutput {
    /// <p>The Amazon Resource Name (ARN) of the predictor backtest export job that you want to export.</p>
    pub fn predictor_backtest_export_job_arn(&self) -> ::std::option::Option<&str> {
        self.predictor_backtest_export_job_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreatePredictorBacktestExportJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreatePredictorBacktestExportJobOutput {
    /// Creates a new builder-style object to manufacture [`CreatePredictorBacktestExportJobOutput`](crate::operation::create_predictor_backtest_export_job::CreatePredictorBacktestExportJobOutput).
    pub fn builder() -> crate::operation::create_predictor_backtest_export_job::builders::CreatePredictorBacktestExportJobOutputBuilder {
        crate::operation::create_predictor_backtest_export_job::builders::CreatePredictorBacktestExportJobOutputBuilder::default()
    }
}

/// A builder for [`CreatePredictorBacktestExportJobOutput`](crate::operation::create_predictor_backtest_export_job::CreatePredictorBacktestExportJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePredictorBacktestExportJobOutputBuilder {
    pub(crate) predictor_backtest_export_job_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePredictorBacktestExportJobOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the predictor backtest export job that you want to export.</p>
    pub fn predictor_backtest_export_job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.predictor_backtest_export_job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the predictor backtest export job that you want to export.</p>
    pub fn set_predictor_backtest_export_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.predictor_backtest_export_job_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the predictor backtest export job that you want to export.</p>
    pub fn get_predictor_backtest_export_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.predictor_backtest_export_job_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreatePredictorBacktestExportJobOutput`](crate::operation::create_predictor_backtest_export_job::CreatePredictorBacktestExportJobOutput).
    pub fn build(self) -> crate::operation::create_predictor_backtest_export_job::CreatePredictorBacktestExportJobOutput {
        crate::operation::create_predictor_backtest_export_job::CreatePredictorBacktestExportJobOutput {
            predictor_backtest_export_job_arn: self.predictor_backtest_export_job_arn,
            _request_id: self._request_id,
        }
    }
}
