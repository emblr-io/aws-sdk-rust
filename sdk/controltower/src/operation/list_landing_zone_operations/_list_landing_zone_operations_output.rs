// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLandingZoneOperationsOutput {
    /// <p>Lists landing zone operations.</p>
    pub landing_zone_operations: ::std::vec::Vec<crate::types::LandingZoneOperationSummary>,
    /// <p>Retrieves the next page of results. If the string is empty, the response is the end of the results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLandingZoneOperationsOutput {
    /// <p>Lists landing zone operations.</p>
    pub fn landing_zone_operations(&self) -> &[crate::types::LandingZoneOperationSummary] {
        use std::ops::Deref;
        self.landing_zone_operations.deref()
    }
    /// <p>Retrieves the next page of results. If the string is empty, the response is the end of the results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListLandingZoneOperationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListLandingZoneOperationsOutput {
    /// Creates a new builder-style object to manufacture [`ListLandingZoneOperationsOutput`](crate::operation::list_landing_zone_operations::ListLandingZoneOperationsOutput).
    pub fn builder() -> crate::operation::list_landing_zone_operations::builders::ListLandingZoneOperationsOutputBuilder {
        crate::operation::list_landing_zone_operations::builders::ListLandingZoneOperationsOutputBuilder::default()
    }
}

/// A builder for [`ListLandingZoneOperationsOutput`](crate::operation::list_landing_zone_operations::ListLandingZoneOperationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLandingZoneOperationsOutputBuilder {
    pub(crate) landing_zone_operations: ::std::option::Option<::std::vec::Vec<crate::types::LandingZoneOperationSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLandingZoneOperationsOutputBuilder {
    /// Appends an item to `landing_zone_operations`.
    ///
    /// To override the contents of this collection use [`set_landing_zone_operations`](Self::set_landing_zone_operations).
    ///
    /// <p>Lists landing zone operations.</p>
    pub fn landing_zone_operations(mut self, input: crate::types::LandingZoneOperationSummary) -> Self {
        let mut v = self.landing_zone_operations.unwrap_or_default();
        v.push(input);
        self.landing_zone_operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Lists landing zone operations.</p>
    pub fn set_landing_zone_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LandingZoneOperationSummary>>) -> Self {
        self.landing_zone_operations = input;
        self
    }
    /// <p>Lists landing zone operations.</p>
    pub fn get_landing_zone_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LandingZoneOperationSummary>> {
        &self.landing_zone_operations
    }
    /// <p>Retrieves the next page of results. If the string is empty, the response is the end of the results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Retrieves the next page of results. If the string is empty, the response is the end of the results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Retrieves the next page of results. If the string is empty, the response is the end of the results.</p>
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
    /// Consumes the builder and constructs a [`ListLandingZoneOperationsOutput`](crate::operation::list_landing_zone_operations::ListLandingZoneOperationsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`landing_zone_operations`](crate::operation::list_landing_zone_operations::builders::ListLandingZoneOperationsOutputBuilder::landing_zone_operations)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_landing_zone_operations::ListLandingZoneOperationsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_landing_zone_operations::ListLandingZoneOperationsOutput {
            landing_zone_operations: self.landing_zone_operations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "landing_zone_operations",
                    "landing_zone_operations was not specified but it is required when building ListLandingZoneOperationsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
