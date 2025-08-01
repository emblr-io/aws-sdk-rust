// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCidrLocationsOutput {
    /// <p>An opaque pagination token to indicate where the service is to begin enumerating results.</p>
    /// <p>If no value is provided, the listing of results starts from the beginning.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A complex type that contains information about the list of CIDR locations.</p>
    pub cidr_locations: ::std::option::Option<::std::vec::Vec<crate::types::LocationSummary>>,
    _request_id: Option<String>,
}
impl ListCidrLocationsOutput {
    /// <p>An opaque pagination token to indicate where the service is to begin enumerating results.</p>
    /// <p>If no value is provided, the listing of results starts from the beginning.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A complex type that contains information about the list of CIDR locations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cidr_locations.is_none()`.
    pub fn cidr_locations(&self) -> &[crate::types::LocationSummary] {
        self.cidr_locations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListCidrLocationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCidrLocationsOutput {
    /// Creates a new builder-style object to manufacture [`ListCidrLocationsOutput`](crate::operation::list_cidr_locations::ListCidrLocationsOutput).
    pub fn builder() -> crate::operation::list_cidr_locations::builders::ListCidrLocationsOutputBuilder {
        crate::operation::list_cidr_locations::builders::ListCidrLocationsOutputBuilder::default()
    }
}

/// A builder for [`ListCidrLocationsOutput`](crate::operation::list_cidr_locations::ListCidrLocationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCidrLocationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) cidr_locations: ::std::option::Option<::std::vec::Vec<crate::types::LocationSummary>>,
    _request_id: Option<String>,
}
impl ListCidrLocationsOutputBuilder {
    /// <p>An opaque pagination token to indicate where the service is to begin enumerating results.</p>
    /// <p>If no value is provided, the listing of results starts from the beginning.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An opaque pagination token to indicate where the service is to begin enumerating results.</p>
    /// <p>If no value is provided, the listing of results starts from the beginning.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An opaque pagination token to indicate where the service is to begin enumerating results.</p>
    /// <p>If no value is provided, the listing of results starts from the beginning.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `cidr_locations`.
    ///
    /// To override the contents of this collection use [`set_cidr_locations`](Self::set_cidr_locations).
    ///
    /// <p>A complex type that contains information about the list of CIDR locations.</p>
    pub fn cidr_locations(mut self, input: crate::types::LocationSummary) -> Self {
        let mut v = self.cidr_locations.unwrap_or_default();
        v.push(input);
        self.cidr_locations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A complex type that contains information about the list of CIDR locations.</p>
    pub fn set_cidr_locations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LocationSummary>>) -> Self {
        self.cidr_locations = input;
        self
    }
    /// <p>A complex type that contains information about the list of CIDR locations.</p>
    pub fn get_cidr_locations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LocationSummary>> {
        &self.cidr_locations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListCidrLocationsOutput`](crate::operation::list_cidr_locations::ListCidrLocationsOutput).
    pub fn build(self) -> crate::operation::list_cidr_locations::ListCidrLocationsOutput {
        crate::operation::list_cidr_locations::ListCidrLocationsOutput {
            next_token: self.next_token,
            cidr_locations: self.cidr_locations,
            _request_id: self._request_id,
        }
    }
}
