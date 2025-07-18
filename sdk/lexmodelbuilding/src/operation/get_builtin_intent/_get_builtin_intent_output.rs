// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBuiltinIntentOutput {
    /// <p>The unique identifier for a built-in intent.</p>
    pub signature: ::std::option::Option<::std::string::String>,
    /// <p>A list of locales that the intent supports.</p>
    pub supported_locales: ::std::option::Option<::std::vec::Vec<crate::types::Locale>>,
    /// <p>An array of <code>BuiltinIntentSlot</code> objects, one entry for each slot type in the intent.</p>
    pub slots: ::std::option::Option<::std::vec::Vec<crate::types::BuiltinIntentSlot>>,
    _request_id: Option<String>,
}
impl GetBuiltinIntentOutput {
    /// <p>The unique identifier for a built-in intent.</p>
    pub fn signature(&self) -> ::std::option::Option<&str> {
        self.signature.as_deref()
    }
    /// <p>A list of locales that the intent supports.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_locales.is_none()`.
    pub fn supported_locales(&self) -> &[crate::types::Locale] {
        self.supported_locales.as_deref().unwrap_or_default()
    }
    /// <p>An array of <code>BuiltinIntentSlot</code> objects, one entry for each slot type in the intent.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.slots.is_none()`.
    pub fn slots(&self) -> &[crate::types::BuiltinIntentSlot] {
        self.slots.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetBuiltinIntentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBuiltinIntentOutput {
    /// Creates a new builder-style object to manufacture [`GetBuiltinIntentOutput`](crate::operation::get_builtin_intent::GetBuiltinIntentOutput).
    pub fn builder() -> crate::operation::get_builtin_intent::builders::GetBuiltinIntentOutputBuilder {
        crate::operation::get_builtin_intent::builders::GetBuiltinIntentOutputBuilder::default()
    }
}

/// A builder for [`GetBuiltinIntentOutput`](crate::operation::get_builtin_intent::GetBuiltinIntentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBuiltinIntentOutputBuilder {
    pub(crate) signature: ::std::option::Option<::std::string::String>,
    pub(crate) supported_locales: ::std::option::Option<::std::vec::Vec<crate::types::Locale>>,
    pub(crate) slots: ::std::option::Option<::std::vec::Vec<crate::types::BuiltinIntentSlot>>,
    _request_id: Option<String>,
}
impl GetBuiltinIntentOutputBuilder {
    /// <p>The unique identifier for a built-in intent.</p>
    pub fn signature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.signature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for a built-in intent.</p>
    pub fn set_signature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.signature = input;
        self
    }
    /// <p>The unique identifier for a built-in intent.</p>
    pub fn get_signature(&self) -> &::std::option::Option<::std::string::String> {
        &self.signature
    }
    /// Appends an item to `supported_locales`.
    ///
    /// To override the contents of this collection use [`set_supported_locales`](Self::set_supported_locales).
    ///
    /// <p>A list of locales that the intent supports.</p>
    pub fn supported_locales(mut self, input: crate::types::Locale) -> Self {
        let mut v = self.supported_locales.unwrap_or_default();
        v.push(input);
        self.supported_locales = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of locales that the intent supports.</p>
    pub fn set_supported_locales(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Locale>>) -> Self {
        self.supported_locales = input;
        self
    }
    /// <p>A list of locales that the intent supports.</p>
    pub fn get_supported_locales(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Locale>> {
        &self.supported_locales
    }
    /// Appends an item to `slots`.
    ///
    /// To override the contents of this collection use [`set_slots`](Self::set_slots).
    ///
    /// <p>An array of <code>BuiltinIntentSlot</code> objects, one entry for each slot type in the intent.</p>
    pub fn slots(mut self, input: crate::types::BuiltinIntentSlot) -> Self {
        let mut v = self.slots.unwrap_or_default();
        v.push(input);
        self.slots = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>BuiltinIntentSlot</code> objects, one entry for each slot type in the intent.</p>
    pub fn set_slots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BuiltinIntentSlot>>) -> Self {
        self.slots = input;
        self
    }
    /// <p>An array of <code>BuiltinIntentSlot</code> objects, one entry for each slot type in the intent.</p>
    pub fn get_slots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BuiltinIntentSlot>> {
        &self.slots
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetBuiltinIntentOutput`](crate::operation::get_builtin_intent::GetBuiltinIntentOutput).
    pub fn build(self) -> crate::operation::get_builtin_intent::GetBuiltinIntentOutput {
        crate::operation::get_builtin_intent::GetBuiltinIntentOutput {
            signature: self.signature,
            supported_locales: self.supported_locales,
            slots: self.slots,
            _request_id: self._request_id,
        }
    }
}
