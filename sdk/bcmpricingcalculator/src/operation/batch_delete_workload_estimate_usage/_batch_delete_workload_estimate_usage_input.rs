// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchDeleteWorkloadEstimateUsageInput {
    /// <p>The ID of the Workload estimate for which you want to delete the modeled usage.</p>
    pub workload_estimate_id: ::std::option::Option<::std::string::String>,
    /// <p>List of usage that you want to delete from the Workload estimate.</p>
    pub ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchDeleteWorkloadEstimateUsageInput {
    /// <p>The ID of the Workload estimate for which you want to delete the modeled usage.</p>
    pub fn workload_estimate_id(&self) -> ::std::option::Option<&str> {
        self.workload_estimate_id.as_deref()
    }
    /// <p>List of usage that you want to delete from the Workload estimate.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ids.is_none()`.
    pub fn ids(&self) -> &[::std::string::String] {
        self.ids.as_deref().unwrap_or_default()
    }
}
impl BatchDeleteWorkloadEstimateUsageInput {
    /// Creates a new builder-style object to manufacture [`BatchDeleteWorkloadEstimateUsageInput`](crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageInput).
    pub fn builder() -> crate::operation::batch_delete_workload_estimate_usage::builders::BatchDeleteWorkloadEstimateUsageInputBuilder {
        crate::operation::batch_delete_workload_estimate_usage::builders::BatchDeleteWorkloadEstimateUsageInputBuilder::default()
    }
}

/// A builder for [`BatchDeleteWorkloadEstimateUsageInput`](crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchDeleteWorkloadEstimateUsageInputBuilder {
    pub(crate) workload_estimate_id: ::std::option::Option<::std::string::String>,
    pub(crate) ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchDeleteWorkloadEstimateUsageInputBuilder {
    /// <p>The ID of the Workload estimate for which you want to delete the modeled usage.</p>
    /// This field is required.
    pub fn workload_estimate_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workload_estimate_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Workload estimate for which you want to delete the modeled usage.</p>
    pub fn set_workload_estimate_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workload_estimate_id = input;
        self
    }
    /// <p>The ID of the Workload estimate for which you want to delete the modeled usage.</p>
    pub fn get_workload_estimate_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workload_estimate_id
    }
    /// Appends an item to `ids`.
    ///
    /// To override the contents of this collection use [`set_ids`](Self::set_ids).
    ///
    /// <p>List of usage that you want to delete from the Workload estimate.</p>
    pub fn ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ids.unwrap_or_default();
        v.push(input.into());
        self.ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of usage that you want to delete from the Workload estimate.</p>
    pub fn set_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ids = input;
        self
    }
    /// <p>List of usage that you want to delete from the Workload estimate.</p>
    pub fn get_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ids
    }
    /// Consumes the builder and constructs a [`BatchDeleteWorkloadEstimateUsageInput`](crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::batch_delete_workload_estimate_usage::BatchDeleteWorkloadEstimateUsageInput {
                workload_estimate_id: self.workload_estimate_id,
                ids: self.ids,
            },
        )
    }
}
