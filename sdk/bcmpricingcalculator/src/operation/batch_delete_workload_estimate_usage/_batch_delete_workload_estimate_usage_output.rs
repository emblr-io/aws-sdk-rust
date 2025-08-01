// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchDeleteWorkloadEstimateUsageOutput {
    /// <p>Returns the list of errors reason and the usage item keys that cannot be deleted from the Workload estimate.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteWorkloadEstimateUsageError>>,
    _request_id: Option<String>,
}
impl BatchDeleteWorkloadEstimateUsageOutput {
    /// <p>Returns the list of errors reason and the usage item keys that cannot be deleted from the Workload estimate.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::BatchDeleteWorkloadEstimateUsageError] {
        self.errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchDeleteWorkloadEstimateUsageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchDeleteWorkloadEstimateUsageOutput {
    /// Creates a new builder-style object to manufacture [`BatchDeleteWorkloadEstimateUsageOutput`](crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageOutput).
    pub fn builder() -> crate::operation::batch_delete_workload_estimate_usage::builders::BatchDeleteWorkloadEstimateUsageOutputBuilder {
        crate::operation::batch_delete_workload_estimate_usage::builders::BatchDeleteWorkloadEstimateUsageOutputBuilder::default()
    }
}

/// A builder for [`BatchDeleteWorkloadEstimateUsageOutput`](crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchDeleteWorkloadEstimateUsageOutputBuilder {
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteWorkloadEstimateUsageError>>,
    _request_id: Option<String>,
}
impl BatchDeleteWorkloadEstimateUsageOutputBuilder {
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>Returns the list of errors reason and the usage item keys that cannot be deleted from the Workload estimate.</p>
    pub fn errors(mut self, input: crate::types::BatchDeleteWorkloadEstimateUsageError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns the list of errors reason and the usage item keys that cannot be deleted from the Workload estimate.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteWorkloadEstimateUsageError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>Returns the list of errors reason and the usage item keys that cannot be deleted from the Workload estimate.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteWorkloadEstimateUsageError>> {
        &self.errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchDeleteWorkloadEstimateUsageOutput`](crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageOutput).
    pub fn build(self) -> crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageOutput {
        crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageOutput {
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
