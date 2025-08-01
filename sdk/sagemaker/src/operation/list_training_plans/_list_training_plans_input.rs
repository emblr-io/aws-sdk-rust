// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTrainingPlansInput {
    /// <p>A token to continue pagination if more results are available.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Filter to list only training plans with an actual start time after this date.</p>
    pub start_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Filter to list only training plans with an actual start time before this date.</p>
    pub start_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The training plan field to sort the results by (e.g., StartTime, Status).</p>
    pub sort_by: ::std::option::Option<crate::types::TrainingPlanSortBy>,
    /// <p>The order to sort the results (Ascending or Descending).</p>
    pub sort_order: ::std::option::Option<crate::types::TrainingPlanSortOrder>,
    /// <p>Additional filters to apply to the list of training plans.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::TrainingPlanFilter>>,
}
impl ListTrainingPlansInput {
    /// <p>A token to continue pagination if more results are available.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Filter to list only training plans with an actual start time after this date.</p>
    pub fn start_time_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time_after.as_ref()
    }
    /// <p>Filter to list only training plans with an actual start time before this date.</p>
    pub fn start_time_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time_before.as_ref()
    }
    /// <p>The training plan field to sort the results by (e.g., StartTime, Status).</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::TrainingPlanSortBy> {
        self.sort_by.as_ref()
    }
    /// <p>The order to sort the results (Ascending or Descending).</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::TrainingPlanSortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>Additional filters to apply to the list of training plans.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::TrainingPlanFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
}
impl ListTrainingPlansInput {
    /// Creates a new builder-style object to manufacture [`ListTrainingPlansInput`](crate::operation::list_training_plans::ListTrainingPlansInput).
    pub fn builder() -> crate::operation::list_training_plans::builders::ListTrainingPlansInputBuilder {
        crate::operation::list_training_plans::builders::ListTrainingPlansInputBuilder::default()
    }
}

/// A builder for [`ListTrainingPlansInput`](crate::operation::list_training_plans::ListTrainingPlansInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTrainingPlansInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) start_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) start_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) sort_by: ::std::option::Option<crate::types::TrainingPlanSortBy>,
    pub(crate) sort_order: ::std::option::Option<crate::types::TrainingPlanSortOrder>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::TrainingPlanFilter>>,
}
impl ListTrainingPlansInputBuilder {
    /// <p>A token to continue pagination if more results are available.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to continue pagination if more results are available.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to continue pagination if more results are available.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Filter to list only training plans with an actual start time after this date.</p>
    pub fn start_time_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter to list only training plans with an actual start time after this date.</p>
    pub fn set_start_time_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time_after = input;
        self
    }
    /// <p>Filter to list only training plans with an actual start time after this date.</p>
    pub fn get_start_time_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time_after
    }
    /// <p>Filter to list only training plans with an actual start time before this date.</p>
    pub fn start_time_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter to list only training plans with an actual start time before this date.</p>
    pub fn set_start_time_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time_before = input;
        self
    }
    /// <p>Filter to list only training plans with an actual start time before this date.</p>
    pub fn get_start_time_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time_before
    }
    /// <p>The training plan field to sort the results by (e.g., StartTime, Status).</p>
    pub fn sort_by(mut self, input: crate::types::TrainingPlanSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The training plan field to sort the results by (e.g., StartTime, Status).</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::TrainingPlanSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The training plan field to sort the results by (e.g., StartTime, Status).</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::TrainingPlanSortBy> {
        &self.sort_by
    }
    /// <p>The order to sort the results (Ascending or Descending).</p>
    pub fn sort_order(mut self, input: crate::types::TrainingPlanSortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order to sort the results (Ascending or Descending).</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::TrainingPlanSortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The order to sort the results (Ascending or Descending).</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::TrainingPlanSortOrder> {
        &self.sort_order
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Additional filters to apply to the list of training plans.</p>
    pub fn filters(mut self, input: crate::types::TrainingPlanFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Additional filters to apply to the list of training plans.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TrainingPlanFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Additional filters to apply to the list of training plans.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TrainingPlanFilter>> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`ListTrainingPlansInput`](crate::operation::list_training_plans::ListTrainingPlansInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_training_plans::ListTrainingPlansInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_training_plans::ListTrainingPlansInput {
            next_token: self.next_token,
            max_results: self.max_results,
            start_time_after: self.start_time_after,
            start_time_before: self.start_time_before,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            filters: self.filters,
        })
    }
}
