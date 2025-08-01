// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListForecastExportJobsOutput {
    /// <p>An array of objects that summarize each export job's properties.</p>
    pub forecast_export_jobs: ::std::option::Option<::std::vec::Vec<crate::types::ForecastExportJobSummary>>,
    /// <p>If the response is truncated, Amazon Forecast returns this token. To retrieve the next set of results, use the token in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListForecastExportJobsOutput {
    /// <p>An array of objects that summarize each export job's properties.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.forecast_export_jobs.is_none()`.
    pub fn forecast_export_jobs(&self) -> &[crate::types::ForecastExportJobSummary] {
        self.forecast_export_jobs.as_deref().unwrap_or_default()
    }
    /// <p>If the response is truncated, Amazon Forecast returns this token. To retrieve the next set of results, use the token in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListForecastExportJobsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListForecastExportJobsOutput {
    /// Creates a new builder-style object to manufacture [`ListForecastExportJobsOutput`](crate::operation::list_forecast_export_jobs::ListForecastExportJobsOutput).
    pub fn builder() -> crate::operation::list_forecast_export_jobs::builders::ListForecastExportJobsOutputBuilder {
        crate::operation::list_forecast_export_jobs::builders::ListForecastExportJobsOutputBuilder::default()
    }
}

/// A builder for [`ListForecastExportJobsOutput`](crate::operation::list_forecast_export_jobs::ListForecastExportJobsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListForecastExportJobsOutputBuilder {
    pub(crate) forecast_export_jobs: ::std::option::Option<::std::vec::Vec<crate::types::ForecastExportJobSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListForecastExportJobsOutputBuilder {
    /// Appends an item to `forecast_export_jobs`.
    ///
    /// To override the contents of this collection use [`set_forecast_export_jobs`](Self::set_forecast_export_jobs).
    ///
    /// <p>An array of objects that summarize each export job's properties.</p>
    pub fn forecast_export_jobs(mut self, input: crate::types::ForecastExportJobSummary) -> Self {
        let mut v = self.forecast_export_jobs.unwrap_or_default();
        v.push(input);
        self.forecast_export_jobs = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that summarize each export job's properties.</p>
    pub fn set_forecast_export_jobs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ForecastExportJobSummary>>) -> Self {
        self.forecast_export_jobs = input;
        self
    }
    /// <p>An array of objects that summarize each export job's properties.</p>
    pub fn get_forecast_export_jobs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ForecastExportJobSummary>> {
        &self.forecast_export_jobs
    }
    /// <p>If the response is truncated, Amazon Forecast returns this token. To retrieve the next set of results, use the token in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, Amazon Forecast returns this token. To retrieve the next set of results, use the token in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, Amazon Forecast returns this token. To retrieve the next set of results, use the token in the next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListForecastExportJobsOutput`](crate::operation::list_forecast_export_jobs::ListForecastExportJobsOutput).
    pub fn build(self) -> crate::operation::list_forecast_export_jobs::ListForecastExportJobsOutput {
        crate::operation::list_forecast_export_jobs::ListForecastExportJobsOutput {
            forecast_export_jobs: self.forecast_export_jobs,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
