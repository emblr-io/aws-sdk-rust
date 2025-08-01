// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchUpdateBillScenarioCommitmentModificationOutput {
    /// <p>Returns the list of successful commitment line items that were updated for a Bill Scenario.</p>
    pub items: ::std::option::Option<::std::vec::Vec<crate::types::BillScenarioCommitmentModificationItem>>,
    /// <p>Returns the list of error reasons and commitment line item IDs that could not be updated for the Bill Scenario.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioCommitmentModificationError>>,
    _request_id: Option<String>,
}
impl BatchUpdateBillScenarioCommitmentModificationOutput {
    /// <p>Returns the list of successful commitment line items that were updated for a Bill Scenario.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[crate::types::BillScenarioCommitmentModificationItem] {
        self.items.as_deref().unwrap_or_default()
    }
    /// <p>Returns the list of error reasons and commitment line item IDs that could not be updated for the Bill Scenario.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::BatchUpdateBillScenarioCommitmentModificationError] {
        self.errors.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchUpdateBillScenarioCommitmentModificationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchUpdateBillScenarioCommitmentModificationOutput {
    /// Creates a new builder-style object to manufacture [`BatchUpdateBillScenarioCommitmentModificationOutput`](crate::operation::batch_update_bill_scenario_commitment_modification::BatchUpdateBillScenarioCommitmentModificationOutput).
    pub fn builder(
    ) -> crate::operation::batch_update_bill_scenario_commitment_modification::builders::BatchUpdateBillScenarioCommitmentModificationOutputBuilder
    {
        crate::operation::batch_update_bill_scenario_commitment_modification::builders::BatchUpdateBillScenarioCommitmentModificationOutputBuilder::default()
    }
}

/// A builder for [`BatchUpdateBillScenarioCommitmentModificationOutput`](crate::operation::batch_update_bill_scenario_commitment_modification::BatchUpdateBillScenarioCommitmentModificationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchUpdateBillScenarioCommitmentModificationOutputBuilder {
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::BillScenarioCommitmentModificationItem>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioCommitmentModificationError>>,
    _request_id: Option<String>,
}
impl BatchUpdateBillScenarioCommitmentModificationOutputBuilder {
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>Returns the list of successful commitment line items that were updated for a Bill Scenario.</p>
    pub fn items(mut self, input: crate::types::BillScenarioCommitmentModificationItem) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns the list of successful commitment line items that were updated for a Bill Scenario.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BillScenarioCommitmentModificationItem>>) -> Self {
        self.items = input;
        self
    }
    /// <p>Returns the list of successful commitment line items that were updated for a Bill Scenario.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BillScenarioCommitmentModificationItem>> {
        &self.items
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>Returns the list of error reasons and commitment line item IDs that could not be updated for the Bill Scenario.</p>
    pub fn errors(mut self, input: crate::types::BatchUpdateBillScenarioCommitmentModificationError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns the list of error reasons and commitment line item IDs that could not be updated for the Bill Scenario.</p>
    pub fn set_errors(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioCommitmentModificationError>>,
    ) -> Self {
        self.errors = input;
        self
    }
    /// <p>Returns the list of error reasons and commitment line item IDs that could not be updated for the Bill Scenario.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioCommitmentModificationError>> {
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
    /// Consumes the builder and constructs a [`BatchUpdateBillScenarioCommitmentModificationOutput`](crate::operation::batch_update_bill_scenario_commitment_modification::BatchUpdateBillScenarioCommitmentModificationOutput).
    pub fn build(self) -> crate::operation::batch_update_bill_scenario_commitment_modification::BatchUpdateBillScenarioCommitmentModificationOutput {
        crate::operation::batch_update_bill_scenario_commitment_modification::BatchUpdateBillScenarioCommitmentModificationOutput {
            items: self.items,
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
