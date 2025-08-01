// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An intent that Amazon Lex suggests satisfies the user's intent. Includes the name of the intent, the confidence that Amazon Lex has that the user's intent is satisfied, and the slots defined for the intent.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct PredictedIntent {
    /// <p>The name of the intent that Amazon Lex suggests satisfies the user's intent.</p>
    pub intent_name: ::std::option::Option<::std::string::String>,
    /// <p>Indicates how confident Amazon Lex is that an intent satisfies the user's intent.</p>
    pub nlu_intent_confidence: ::std::option::Option<crate::types::IntentConfidence>,
    /// <p>The slot and slot values associated with the predicted intent.</p>
    pub slots: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PredictedIntent {
    /// <p>The name of the intent that Amazon Lex suggests satisfies the user's intent.</p>
    pub fn intent_name(&self) -> ::std::option::Option<&str> {
        self.intent_name.as_deref()
    }
    /// <p>Indicates how confident Amazon Lex is that an intent satisfies the user's intent.</p>
    pub fn nlu_intent_confidence(&self) -> ::std::option::Option<&crate::types::IntentConfidence> {
        self.nlu_intent_confidence.as_ref()
    }
    /// <p>The slot and slot values associated with the predicted intent.</p>
    pub fn slots(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.slots.as_ref()
    }
}
impl ::std::fmt::Debug for PredictedIntent {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PredictedIntent");
        formatter.field("intent_name", &self.intent_name);
        formatter.field("nlu_intent_confidence", &self.nlu_intent_confidence);
        formatter.field("slots", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl PredictedIntent {
    /// Creates a new builder-style object to manufacture [`PredictedIntent`](crate::types::PredictedIntent).
    pub fn builder() -> crate::types::builders::PredictedIntentBuilder {
        crate::types::builders::PredictedIntentBuilder::default()
    }
}

/// A builder for [`PredictedIntent`](crate::types::PredictedIntent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct PredictedIntentBuilder {
    pub(crate) intent_name: ::std::option::Option<::std::string::String>,
    pub(crate) nlu_intent_confidence: ::std::option::Option<crate::types::IntentConfidence>,
    pub(crate) slots: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl PredictedIntentBuilder {
    /// <p>The name of the intent that Amazon Lex suggests satisfies the user's intent.</p>
    pub fn intent_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.intent_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the intent that Amazon Lex suggests satisfies the user's intent.</p>
    pub fn set_intent_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.intent_name = input;
        self
    }
    /// <p>The name of the intent that Amazon Lex suggests satisfies the user's intent.</p>
    pub fn get_intent_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.intent_name
    }
    /// <p>Indicates how confident Amazon Lex is that an intent satisfies the user's intent.</p>
    pub fn nlu_intent_confidence(mut self, input: crate::types::IntentConfidence) -> Self {
        self.nlu_intent_confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates how confident Amazon Lex is that an intent satisfies the user's intent.</p>
    pub fn set_nlu_intent_confidence(mut self, input: ::std::option::Option<crate::types::IntentConfidence>) -> Self {
        self.nlu_intent_confidence = input;
        self
    }
    /// <p>Indicates how confident Amazon Lex is that an intent satisfies the user's intent.</p>
    pub fn get_nlu_intent_confidence(&self) -> &::std::option::Option<crate::types::IntentConfidence> {
        &self.nlu_intent_confidence
    }
    /// Adds a key-value pair to `slots`.
    ///
    /// To override the contents of this collection use [`set_slots`](Self::set_slots).
    ///
    /// <p>The slot and slot values associated with the predicted intent.</p>
    pub fn slots(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.slots.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.slots = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The slot and slot values associated with the predicted intent.</p>
    pub fn set_slots(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.slots = input;
        self
    }
    /// <p>The slot and slot values associated with the predicted intent.</p>
    pub fn get_slots(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.slots
    }
    /// Consumes the builder and constructs a [`PredictedIntent`](crate::types::PredictedIntent).
    pub fn build(self) -> crate::types::PredictedIntent {
        crate::types::PredictedIntent {
            intent_name: self.intent_name,
            nlu_intent_confidence: self.nlu_intent_confidence,
            slots: self.slots,
        }
    }
}
impl ::std::fmt::Debug for PredictedIntentBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PredictedIntentBuilder");
        formatter.field("intent_name", &self.intent_name);
        formatter.field("nlu_intent_confidence", &self.nlu_intent_confidence);
        formatter.field("slots", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
