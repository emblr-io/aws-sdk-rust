// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetReservationCoverageOutput {
    /// <p>The amount of time that your reservations covered.</p>
    pub coverages_by_time: ::std::vec::Vec<crate::types::CoverageByTime>,
    /// <p>The total amount of instance usage that a reservation covered.</p>
    pub total: ::std::option::Option<crate::types::Coverage>,
    /// <p>The token for the next set of retrievable results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetReservationCoverageOutput {
    /// <p>The amount of time that your reservations covered.</p>
    pub fn coverages_by_time(&self) -> &[crate::types::CoverageByTime] {
        use std::ops::Deref;
        self.coverages_by_time.deref()
    }
    /// <p>The total amount of instance usage that a reservation covered.</p>
    pub fn total(&self) -> ::std::option::Option<&crate::types::Coverage> {
        self.total.as_ref()
    }
    /// <p>The token for the next set of retrievable results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetReservationCoverageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetReservationCoverageOutput {
    /// Creates a new builder-style object to manufacture [`GetReservationCoverageOutput`](crate::operation::get_reservation_coverage::GetReservationCoverageOutput).
    pub fn builder() -> crate::operation::get_reservation_coverage::builders::GetReservationCoverageOutputBuilder {
        crate::operation::get_reservation_coverage::builders::GetReservationCoverageOutputBuilder::default()
    }
}

/// A builder for [`GetReservationCoverageOutput`](crate::operation::get_reservation_coverage::GetReservationCoverageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetReservationCoverageOutputBuilder {
    pub(crate) coverages_by_time: ::std::option::Option<::std::vec::Vec<crate::types::CoverageByTime>>,
    pub(crate) total: ::std::option::Option<crate::types::Coverage>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetReservationCoverageOutputBuilder {
    /// Appends an item to `coverages_by_time`.
    ///
    /// To override the contents of this collection use [`set_coverages_by_time`](Self::set_coverages_by_time).
    ///
    /// <p>The amount of time that your reservations covered.</p>
    pub fn coverages_by_time(mut self, input: crate::types::CoverageByTime) -> Self {
        let mut v = self.coverages_by_time.unwrap_or_default();
        v.push(input);
        self.coverages_by_time = ::std::option::Option::Some(v);
        self
    }
    /// <p>The amount of time that your reservations covered.</p>
    pub fn set_coverages_by_time(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CoverageByTime>>) -> Self {
        self.coverages_by_time = input;
        self
    }
    /// <p>The amount of time that your reservations covered.</p>
    pub fn get_coverages_by_time(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CoverageByTime>> {
        &self.coverages_by_time
    }
    /// <p>The total amount of instance usage that a reservation covered.</p>
    pub fn total(mut self, input: crate::types::Coverage) -> Self {
        self.total = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total amount of instance usage that a reservation covered.</p>
    pub fn set_total(mut self, input: ::std::option::Option<crate::types::Coverage>) -> Self {
        self.total = input;
        self
    }
    /// <p>The total amount of instance usage that a reservation covered.</p>
    pub fn get_total(&self) -> &::std::option::Option<crate::types::Coverage> {
        &self.total
    }
    /// <p>The token for the next set of retrievable results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of retrievable results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token for the next set of retrievable results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetReservationCoverageOutput`](crate::operation::get_reservation_coverage::GetReservationCoverageOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`coverages_by_time`](crate::operation::get_reservation_coverage::builders::GetReservationCoverageOutputBuilder::coverages_by_time)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_reservation_coverage::GetReservationCoverageOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_reservation_coverage::GetReservationCoverageOutput {
            coverages_by_time: self.coverages_by_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "coverages_by_time",
                    "coverages_by_time was not specified but it is required when building GetReservationCoverageOutput",
                )
            })?,
            total: self.total,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        })
    }
}
