// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>You can provide Amazon Lex with hints to the phrases that a customer is likely to use for a slot. When a slot with hints is resolved, the phrases in the runtime hints are preferred in the resolution. You can provide hints for a maximum of 100 intents. You can provide a maximum of 100 slots.</p>
/// <p>Before you can use runtime hints with an existing bot, you must first rebuild the bot.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/using-hints.html">Using runtime hints to improve recognition of slot values</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuntimeHints {
    /// <p>A list of the slots in the intent that should have runtime hints added, and the phrases that should be added for each slot.</p>
    /// <p>The first level of the <code>slotHints</code> map is the name of the intent. The second level is the name of the slot within the intent. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/using-hints.html">Using hints to improve accuracy</a>.</p>
    /// <p>The intent name and slot name must exist.</p>
    pub slot_hints: ::std::option::Option<
        ::std::collections::HashMap<::std::string::String, ::std::collections::HashMap<::std::string::String, crate::types::RuntimeHintDetails>>,
    >,
}
impl RuntimeHints {
    /// <p>A list of the slots in the intent that should have runtime hints added, and the phrases that should be added for each slot.</p>
    /// <p>The first level of the <code>slotHints</code> map is the name of the intent. The second level is the name of the slot within the intent. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/using-hints.html">Using hints to improve accuracy</a>.</p>
    /// <p>The intent name and slot name must exist.</p>
    pub fn slot_hints(
        &self,
    ) -> ::std::option::Option<
        &::std::collections::HashMap<::std::string::String, ::std::collections::HashMap<::std::string::String, crate::types::RuntimeHintDetails>>,
    > {
        self.slot_hints.as_ref()
    }
}
impl RuntimeHints {
    /// Creates a new builder-style object to manufacture [`RuntimeHints`](crate::types::RuntimeHints).
    pub fn builder() -> crate::types::builders::RuntimeHintsBuilder {
        crate::types::builders::RuntimeHintsBuilder::default()
    }
}

/// A builder for [`RuntimeHints`](crate::types::RuntimeHints).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuntimeHintsBuilder {
    pub(crate) slot_hints: ::std::option::Option<
        ::std::collections::HashMap<::std::string::String, ::std::collections::HashMap<::std::string::String, crate::types::RuntimeHintDetails>>,
    >,
}
impl RuntimeHintsBuilder {
    /// Adds a key-value pair to `slot_hints`.
    ///
    /// To override the contents of this collection use [`set_slot_hints`](Self::set_slot_hints).
    ///
    /// <p>A list of the slots in the intent that should have runtime hints added, and the phrases that should be added for each slot.</p>
    /// <p>The first level of the <code>slotHints</code> map is the name of the intent. The second level is the name of the slot within the intent. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/using-hints.html">Using hints to improve accuracy</a>.</p>
    /// <p>The intent name and slot name must exist.</p>
    pub fn slot_hints(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: ::std::collections::HashMap<::std::string::String, crate::types::RuntimeHintDetails>,
    ) -> Self {
        let mut hash_map = self.slot_hints.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.slot_hints = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of the slots in the intent that should have runtime hints added, and the phrases that should be added for each slot.</p>
    /// <p>The first level of the <code>slotHints</code> map is the name of the intent. The second level is the name of the slot within the intent. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/using-hints.html">Using hints to improve accuracy</a>.</p>
    /// <p>The intent name and slot name must exist.</p>
    pub fn set_slot_hints(
        mut self,
        input: ::std::option::Option<
            ::std::collections::HashMap<::std::string::String, ::std::collections::HashMap<::std::string::String, crate::types::RuntimeHintDetails>>,
        >,
    ) -> Self {
        self.slot_hints = input;
        self
    }
    /// <p>A list of the slots in the intent that should have runtime hints added, and the phrases that should be added for each slot.</p>
    /// <p>The first level of the <code>slotHints</code> map is the name of the intent. The second level is the name of the slot within the intent. For more information, see <a href="https://docs.aws.amazon.com/lexv2/latest/dg/using-hints.html">Using hints to improve accuracy</a>.</p>
    /// <p>The intent name and slot name must exist.</p>
    pub fn get_slot_hints(
        &self,
    ) -> &::std::option::Option<
        ::std::collections::HashMap<::std::string::String, ::std::collections::HashMap<::std::string::String, crate::types::RuntimeHintDetails>>,
    > {
        &self.slot_hints
    }
    /// Consumes the builder and constructs a [`RuntimeHints`](crate::types::RuntimeHints).
    pub fn build(self) -> crate::types::RuntimeHints {
        crate::types::RuntimeHints { slot_hints: self.slot_hints }
    }
}
