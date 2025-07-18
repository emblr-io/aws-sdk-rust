// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to obtain a list of email destinations that are on the suppression list for your account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSuppressedDestinationsInput {
    /// <p>The factors that caused the email address to be added to .</p>
    pub reasons: ::std::option::Option<::std::vec::Vec<crate::types::SuppressionListReason>>,
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list after a specific date.</p>
    pub start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list before a specific date.</p>
    pub end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A token returned from a previous call to <code>ListSuppressedDestinations</code> to indicate the position in the list of suppressed email addresses.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The number of results to show in a single call to <code>ListSuppressedDestinations</code>. If the number of results is larger than the number you specified in this parameter, then the response includes a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub page_size: ::std::option::Option<i32>,
}
impl ListSuppressedDestinationsInput {
    /// <p>The factors that caused the email address to be added to .</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reasons.is_none()`.
    pub fn reasons(&self) -> &[crate::types::SuppressionListReason] {
        self.reasons.as_deref().unwrap_or_default()
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list after a specific date.</p>
    pub fn start_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_date.as_ref()
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list before a specific date.</p>
    pub fn end_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_date.as_ref()
    }
    /// <p>A token returned from a previous call to <code>ListSuppressedDestinations</code> to indicate the position in the list of suppressed email addresses.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The number of results to show in a single call to <code>ListSuppressedDestinations</code>. If the number of results is larger than the number you specified in this parameter, then the response includes a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
}
impl ListSuppressedDestinationsInput {
    /// Creates a new builder-style object to manufacture [`ListSuppressedDestinationsInput`](crate::operation::list_suppressed_destinations::ListSuppressedDestinationsInput).
    pub fn builder() -> crate::operation::list_suppressed_destinations::builders::ListSuppressedDestinationsInputBuilder {
        crate::operation::list_suppressed_destinations::builders::ListSuppressedDestinationsInputBuilder::default()
    }
}

/// A builder for [`ListSuppressedDestinationsInput`](crate::operation::list_suppressed_destinations::ListSuppressedDestinationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSuppressedDestinationsInputBuilder {
    pub(crate) reasons: ::std::option::Option<::std::vec::Vec<crate::types::SuppressionListReason>>,
    pub(crate) start_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) page_size: ::std::option::Option<i32>,
}
impl ListSuppressedDestinationsInputBuilder {
    /// Appends an item to `reasons`.
    ///
    /// To override the contents of this collection use [`set_reasons`](Self::set_reasons).
    ///
    /// <p>The factors that caused the email address to be added to .</p>
    pub fn reasons(mut self, input: crate::types::SuppressionListReason) -> Self {
        let mut v = self.reasons.unwrap_or_default();
        v.push(input);
        self.reasons = ::std::option::Option::Some(v);
        self
    }
    /// <p>The factors that caused the email address to be added to .</p>
    pub fn set_reasons(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SuppressionListReason>>) -> Self {
        self.reasons = input;
        self
    }
    /// <p>The factors that caused the email address to be added to .</p>
    pub fn get_reasons(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SuppressionListReason>> {
        &self.reasons
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list after a specific date.</p>
    pub fn start_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list after a specific date.</p>
    pub fn set_start_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list after a specific date.</p>
    pub fn get_start_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_date
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list before a specific date.</p>
    pub fn end_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list before a specific date.</p>
    pub fn set_end_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_date = input;
        self
    }
    /// <p>Used to filter the list of suppressed email destinations so that it only includes addresses that were added to the list before a specific date.</p>
    pub fn get_end_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_date
    }
    /// <p>A token returned from a previous call to <code>ListSuppressedDestinations</code> to indicate the position in the list of suppressed email addresses.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token returned from a previous call to <code>ListSuppressedDestinations</code> to indicate the position in the list of suppressed email addresses.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token returned from a previous call to <code>ListSuppressedDestinations</code> to indicate the position in the list of suppressed email addresses.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The number of results to show in a single call to <code>ListSuppressedDestinations</code>. If the number of results is larger than the number you specified in this parameter, then the response includes a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of results to show in a single call to <code>ListSuppressedDestinations</code>. If the number of results is larger than the number you specified in this parameter, then the response includes a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>The number of results to show in a single call to <code>ListSuppressedDestinations</code>. If the number of results is larger than the number you specified in this parameter, then the response includes a <code>NextToken</code> element, which you can use to obtain additional results.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// Consumes the builder and constructs a [`ListSuppressedDestinationsInput`](crate::operation::list_suppressed_destinations::ListSuppressedDestinationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_suppressed_destinations::ListSuppressedDestinationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_suppressed_destinations::ListSuppressedDestinationsInput {
            reasons: self.reasons,
            start_date: self.start_date,
            end_date: self.end_date,
            next_token: self.next_token,
            page_size: self.page_size,
        })
    }
}
