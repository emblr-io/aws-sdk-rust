// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchDeleteBillScenarioCommitmentModificationOutput {
    /// <p>Returns the list of errors reason and the commitment item keys that cannot be deleted from the Bill Scenario.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteBillScenarioCommitmentModificationError>>,
    _request_id: Option<String>,
}
impl BatchDeleteBillScenarioCommitmentModificationOutput {
    /// <p>Returns the list of errors reason and the commitment item keys that cannot be deleted from the Bill Scenario.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::BatchDeleteBillScenarioCommitmentModificationError] {
        self.errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchDeleteBillScenarioCommitmentModificationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchDeleteBillScenarioCommitmentModificationOutput {
    /// Creates a new builder-style object to manufacture [`BatchDeleteBillScenarioCommitmentModificationOutput`](crate::operation::batch_delete_bill_scenario_commitment_modification::BatchDeleteBillScenarioCommitmentModificationOutput).
    pub fn builder(
    ) -> crate::operation::batch_delete_bill_scenario_commitment_modification::builders::BatchDeleteBillScenarioCommitmentModificationOutputBuilder
    {
        crate::operation::batch_delete_bill_scenario_commitment_modification::builders::BatchDeleteBillScenarioCommitmentModificationOutputBuilder::default()
    }
}

/// A builder for [`BatchDeleteBillScenarioCommitmentModificationOutput`](crate::operation::batch_delete_bill_scenario_commitment_modification::BatchDeleteBillScenarioCommitmentModificationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchDeleteBillScenarioCommitmentModificationOutputBuilder {
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteBillScenarioCommitmentModificationError>>,
    _request_id: Option<String>,
}
impl BatchDeleteBillScenarioCommitmentModificationOutputBuilder {
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>Returns the list of errors reason and the commitment item keys that cannot be deleted from the Bill Scenario.</p>
    pub fn errors(mut self, input: crate::types::BatchDeleteBillScenarioCommitmentModificationError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns the list of errors reason and the commitment item keys that cannot be deleted from the Bill Scenario.</p>
    pub fn set_errors(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteBillScenarioCommitmentModificationError>>,
    ) -> Self {
        self.errors = input;
        self
    }
    /// <p>Returns the list of errors reason and the commitment item keys that cannot be deleted from the Bill Scenario.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchDeleteBillScenarioCommitmentModificationError>> {
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
    /// Consumes the builder and constructs a [`BatchDeleteBillScenarioCommitmentModificationOutput`](crate::operation::batch_delete_bill_scenario_commitment_modification::BatchDeleteBillScenarioCommitmentModificationOutput).
    pub fn build(self) -> crate::operation::batch_delete_bill_scenario_commitment_modification::BatchDeleteBillScenarioCommitmentModificationOutput {
        crate::operation::batch_delete_bill_scenario_commitment_modification::BatchDeleteBillScenarioCommitmentModificationOutput {
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
