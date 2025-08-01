// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchUpdateBillScenarioUsageModificationInput {
    /// <p>The ID of the Bill Scenario for which you want to modify the usage lines.</p>
    pub bill_scenario_id: ::std::option::Option<::std::string::String>,
    /// <p>List of usage lines that you want to update in a Bill Scenario identified by the usage ID.</p>
    pub usage_modifications: ::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioUsageModificationEntry>>,
}
impl BatchUpdateBillScenarioUsageModificationInput {
    /// <p>The ID of the Bill Scenario for which you want to modify the usage lines.</p>
    pub fn bill_scenario_id(&self) -> ::std::option::Option<&str> {
        self.bill_scenario_id.as_deref()
    }
    /// <p>List of usage lines that you want to update in a Bill Scenario identified by the usage ID.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.usage_modifications.is_none()`.
    pub fn usage_modifications(&self) -> &[crate::types::BatchUpdateBillScenarioUsageModificationEntry] {
        self.usage_modifications.as_deref().unwrap_or_default()
    }
}
impl BatchUpdateBillScenarioUsageModificationInput {
    /// Creates a new builder-style object to manufacture [`BatchUpdateBillScenarioUsageModificationInput`](crate::operation::batch_update_bill_scenario_usage_modification::BatchUpdateBillScenarioUsageModificationInput).
    pub fn builder() -> crate::operation::batch_update_bill_scenario_usage_modification::builders::BatchUpdateBillScenarioUsageModificationInputBuilder
    {
        crate::operation::batch_update_bill_scenario_usage_modification::builders::BatchUpdateBillScenarioUsageModificationInputBuilder::default()
    }
}

/// A builder for [`BatchUpdateBillScenarioUsageModificationInput`](crate::operation::batch_update_bill_scenario_usage_modification::BatchUpdateBillScenarioUsageModificationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchUpdateBillScenarioUsageModificationInputBuilder {
    pub(crate) bill_scenario_id: ::std::option::Option<::std::string::String>,
    pub(crate) usage_modifications: ::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioUsageModificationEntry>>,
}
impl BatchUpdateBillScenarioUsageModificationInputBuilder {
    /// <p>The ID of the Bill Scenario for which you want to modify the usage lines.</p>
    /// This field is required.
    pub fn bill_scenario_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bill_scenario_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Bill Scenario for which you want to modify the usage lines.</p>
    pub fn set_bill_scenario_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bill_scenario_id = input;
        self
    }
    /// <p>The ID of the Bill Scenario for which you want to modify the usage lines.</p>
    pub fn get_bill_scenario_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bill_scenario_id
    }
    /// Appends an item to `usage_modifications`.
    ///
    /// To override the contents of this collection use [`set_usage_modifications`](Self::set_usage_modifications).
    ///
    /// <p>List of usage lines that you want to update in a Bill Scenario identified by the usage ID.</p>
    pub fn usage_modifications(mut self, input: crate::types::BatchUpdateBillScenarioUsageModificationEntry) -> Self {
        let mut v = self.usage_modifications.unwrap_or_default();
        v.push(input);
        self.usage_modifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of usage lines that you want to update in a Bill Scenario identified by the usage ID.</p>
    pub fn set_usage_modifications(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioUsageModificationEntry>>,
    ) -> Self {
        self.usage_modifications = input;
        self
    }
    /// <p>List of usage lines that you want to update in a Bill Scenario identified by the usage ID.</p>
    pub fn get_usage_modifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchUpdateBillScenarioUsageModificationEntry>> {
        &self.usage_modifications
    }
    /// Consumes the builder and constructs a [`BatchUpdateBillScenarioUsageModificationInput`](crate::operation::batch_update_bill_scenario_usage_modification::BatchUpdateBillScenarioUsageModificationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_update_bill_scenario_usage_modification::BatchUpdateBillScenarioUsageModificationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::batch_update_bill_scenario_usage_modification::BatchUpdateBillScenarioUsageModificationInput {
                bill_scenario_id: self.bill_scenario_id,
                usage_modifications: self.usage_modifications,
            },
        )
    }
}
