// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFleetsForVehicleOutput {
    /// <p>A list of fleet IDs that the vehicle is associated with.</p>
    pub fleets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The token to retrieve the next set of results, or <code>null</code> if there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFleetsForVehicleOutput {
    /// <p>A list of fleet IDs that the vehicle is associated with.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fleets.is_none()`.
    pub fn fleets(&self) -> &[::std::string::String] {
        self.fleets.as_deref().unwrap_or_default()
    }
    /// <p>The token to retrieve the next set of results, or <code>null</code> if there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListFleetsForVehicleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFleetsForVehicleOutput {
    /// Creates a new builder-style object to manufacture [`ListFleetsForVehicleOutput`](crate::operation::list_fleets_for_vehicle::ListFleetsForVehicleOutput).
    pub fn builder() -> crate::operation::list_fleets_for_vehicle::builders::ListFleetsForVehicleOutputBuilder {
        crate::operation::list_fleets_for_vehicle::builders::ListFleetsForVehicleOutputBuilder::default()
    }
}

/// A builder for [`ListFleetsForVehicleOutput`](crate::operation::list_fleets_for_vehicle::ListFleetsForVehicleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFleetsForVehicleOutputBuilder {
    pub(crate) fleets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFleetsForVehicleOutputBuilder {
    /// Appends an item to `fleets`.
    ///
    /// To override the contents of this collection use [`set_fleets`](Self::set_fleets).
    ///
    /// <p>A list of fleet IDs that the vehicle is associated with.</p>
    pub fn fleets(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.fleets.unwrap_or_default();
        v.push(input.into());
        self.fleets = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of fleet IDs that the vehicle is associated with.</p>
    pub fn set_fleets(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.fleets = input;
        self
    }
    /// <p>A list of fleet IDs that the vehicle is associated with.</p>
    pub fn get_fleets(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.fleets
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
    /// Consumes the builder and constructs a [`ListFleetsForVehicleOutput`](crate::operation::list_fleets_for_vehicle::ListFleetsForVehicleOutput).
    pub fn build(self) -> crate::operation::list_fleets_for_vehicle::ListFleetsForVehicleOutput {
        crate::operation::list_fleets_for_vehicle::ListFleetsForVehicleOutput {
            fleets: self.fleets,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
