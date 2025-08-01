// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAssignmentsForHitInput {
    /// <p>The ID of the HIT.</p>
    pub hit_id: ::std::option::Option<::std::string::String>,
    /// <p>Pagination token</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub max_results: ::std::option::Option<i32>,
    /// <p>The status of the assignments to return: Submitted | Approved | Rejected</p>
    pub assignment_statuses: ::std::option::Option<::std::vec::Vec<crate::types::AssignmentStatus>>,
}
impl ListAssignmentsForHitInput {
    /// <p>The ID of the HIT.</p>
    pub fn hit_id(&self) -> ::std::option::Option<&str> {
        self.hit_id.as_deref()
    }
    /// <p>Pagination token</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The status of the assignments to return: Submitted | Approved | Rejected</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.assignment_statuses.is_none()`.
    pub fn assignment_statuses(&self) -> &[crate::types::AssignmentStatus] {
        self.assignment_statuses.as_deref().unwrap_or_default()
    }
}
impl ListAssignmentsForHitInput {
    /// Creates a new builder-style object to manufacture [`ListAssignmentsForHitInput`](crate::operation::list_assignments_for_hit::ListAssignmentsForHitInput).
    pub fn builder() -> crate::operation::list_assignments_for_hit::builders::ListAssignmentsForHitInputBuilder {
        crate::operation::list_assignments_for_hit::builders::ListAssignmentsForHitInputBuilder::default()
    }
}

/// A builder for [`ListAssignmentsForHitInput`](crate::operation::list_assignments_for_hit::ListAssignmentsForHitInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAssignmentsForHitInputBuilder {
    pub(crate) hit_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) assignment_statuses: ::std::option::Option<::std::vec::Vec<crate::types::AssignmentStatus>>,
}
impl ListAssignmentsForHitInputBuilder {
    /// <p>The ID of the HIT.</p>
    /// This field is required.
    pub fn hit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the HIT.</p>
    pub fn set_hit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hit_id = input;
        self
    }
    /// <p>The ID of the HIT.</p>
    pub fn get_hit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hit_id
    }
    /// <p>Pagination token</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Pagination token</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Pagination token</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `assignment_statuses`.
    ///
    /// To override the contents of this collection use [`set_assignment_statuses`](Self::set_assignment_statuses).
    ///
    /// <p>The status of the assignments to return: Submitted | Approved | Rejected</p>
    pub fn assignment_statuses(mut self, input: crate::types::AssignmentStatus) -> Self {
        let mut v = self.assignment_statuses.unwrap_or_default();
        v.push(input);
        self.assignment_statuses = ::std::option::Option::Some(v);
        self
    }
    /// <p>The status of the assignments to return: Submitted | Approved | Rejected</p>
    pub fn set_assignment_statuses(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AssignmentStatus>>) -> Self {
        self.assignment_statuses = input;
        self
    }
    /// <p>The status of the assignments to return: Submitted | Approved | Rejected</p>
    pub fn get_assignment_statuses(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssignmentStatus>> {
        &self.assignment_statuses
    }
    /// Consumes the builder and constructs a [`ListAssignmentsForHitInput`](crate::operation::list_assignments_for_hit::ListAssignmentsForHitInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_assignments_for_hit::ListAssignmentsForHitInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_assignments_for_hit::ListAssignmentsForHitInput {
            hit_id: self.hit_id,
            next_token: self.next_token,
            max_results: self.max_results,
            assignment_statuses: self.assignment_statuses,
        })
    }
}
