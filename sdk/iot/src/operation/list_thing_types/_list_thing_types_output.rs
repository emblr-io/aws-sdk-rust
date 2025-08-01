// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The output for the ListThingTypes operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListThingTypesOutput {
    /// <p>The thing types.</p>
    pub thing_types: ::std::option::Option<::std::vec::Vec<crate::types::ThingTypeDefinition>>,
    /// <p>The token for the next set of results. Will not be returned if operation has returned all results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListThingTypesOutput {
    /// <p>The thing types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.thing_types.is_none()`.
    pub fn thing_types(&self) -> &[crate::types::ThingTypeDefinition] {
        self.thing_types.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results. Will not be returned if operation has returned all results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListThingTypesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListThingTypesOutput {
    /// Creates a new builder-style object to manufacture [`ListThingTypesOutput`](crate::operation::list_thing_types::ListThingTypesOutput).
    pub fn builder() -> crate::operation::list_thing_types::builders::ListThingTypesOutputBuilder {
        crate::operation::list_thing_types::builders::ListThingTypesOutputBuilder::default()
    }
}

/// A builder for [`ListThingTypesOutput`](crate::operation::list_thing_types::ListThingTypesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListThingTypesOutputBuilder {
    pub(crate) thing_types: ::std::option::Option<::std::vec::Vec<crate::types::ThingTypeDefinition>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListThingTypesOutputBuilder {
    /// Appends an item to `thing_types`.
    ///
    /// To override the contents of this collection use [`set_thing_types`](Self::set_thing_types).
    ///
    /// <p>The thing types.</p>
    pub fn thing_types(mut self, input: crate::types::ThingTypeDefinition) -> Self {
        let mut v = self.thing_types.unwrap_or_default();
        v.push(input);
        self.thing_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The thing types.</p>
    pub fn set_thing_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ThingTypeDefinition>>) -> Self {
        self.thing_types = input;
        self
    }
    /// <p>The thing types.</p>
    pub fn get_thing_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ThingTypeDefinition>> {
        &self.thing_types
    }
    /// <p>The token for the next set of results. Will not be returned if operation has returned all results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Will not be returned if operation has returned all results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Will not be returned if operation has returned all results.</p>
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
    /// Consumes the builder and constructs a [`ListThingTypesOutput`](crate::operation::list_thing_types::ListThingTypesOutput).
    pub fn build(self) -> crate::operation::list_thing_types::ListThingTypesOutput {
        crate::operation::list_thing_types::ListThingTypesOutput {
            thing_types: self.thing_types,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
