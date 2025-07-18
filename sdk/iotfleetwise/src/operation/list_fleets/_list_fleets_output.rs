// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFleetsOutput {
    /// <p>A list of information for each fleet.</p>
    pub fleet_summaries: ::std::option::Option<::std::vec::Vec<crate::types::FleetSummary>>,
    /// <p>The token to retrieve the next set of results, or <code>null</code> if there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFleetsOutput {
    /// <p>A list of information for each fleet.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fleet_summaries.is_none()`.
    pub fn fleet_summaries(&self) -> &[crate::types::FleetSummary] {
        self.fleet_summaries.as_deref().unwrap_or_default()
    }
    /// <p>The token to retrieve the next set of results, or <code>null</code> if there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListFleetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFleetsOutput {
    /// Creates a new builder-style object to manufacture [`ListFleetsOutput`](crate::operation::list_fleets::ListFleetsOutput).
    pub fn builder() -> crate::operation::list_fleets::builders::ListFleetsOutputBuilder {
        crate::operation::list_fleets::builders::ListFleetsOutputBuilder::default()
    }
}

/// A builder for [`ListFleetsOutput`](crate::operation::list_fleets::ListFleetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFleetsOutputBuilder {
    pub(crate) fleet_summaries: ::std::option::Option<::std::vec::Vec<crate::types::FleetSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFleetsOutputBuilder {
    /// Appends an item to `fleet_summaries`.
    ///
    /// To override the contents of this collection use [`set_fleet_summaries`](Self::set_fleet_summaries).
    ///
    /// <p>A list of information for each fleet.</p>
    pub fn fleet_summaries(mut self, input: crate::types::FleetSummary) -> Self {
        let mut v = self.fleet_summaries.unwrap_or_default();
        v.push(input);
        self.fleet_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of information for each fleet.</p>
    pub fn set_fleet_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FleetSummary>>) -> Self {
        self.fleet_summaries = input;
        self
    }
    /// <p>A list of information for each fleet.</p>
    pub fn get_fleet_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FleetSummary>> {
        &self.fleet_summaries
    }
    /// <p>The token to retrieve the next set of results, or <code>null</code> if there are no more results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to retrieve the next set of results, or <code>null</code> if there are no more results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to retrieve the next set of results, or <code>null</code> if there are no more results.</p>
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
    /// Consumes the builder and constructs a [`ListFleetsOutput`](crate::operation::list_fleets::ListFleetsOutput).
    pub fn build(self) -> crate::operation::list_fleets::ListFleetsOutput {
        crate::operation::list_fleets::ListFleetsOutput {
            fleet_summaries: self.fleet_summaries,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
