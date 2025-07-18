// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Splice insert message configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SpliceInsertMessage {
    /// <p>This is written to <code>splice_insert.avail_num</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub avail_num: ::std::option::Option<i32>,
    /// <p>This is written to <code>splice_insert.avails_expected</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub avails_expected: ::std::option::Option<i32>,
    /// <p>This is written to <code>splice_insert.splice_event_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>1</code>.</p>
    pub splice_event_id: ::std::option::Option<i32>,
    /// <p>This is written to <code>splice_insert.unique_program_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub unique_program_id: ::std::option::Option<i32>,
}
impl SpliceInsertMessage {
    /// <p>This is written to <code>splice_insert.avail_num</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn avail_num(&self) -> ::std::option::Option<i32> {
        self.avail_num
    }
    /// <p>This is written to <code>splice_insert.avails_expected</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn avails_expected(&self) -> ::std::option::Option<i32> {
        self.avails_expected
    }
    /// <p>This is written to <code>splice_insert.splice_event_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>1</code>.</p>
    pub fn splice_event_id(&self) -> ::std::option::Option<i32> {
        self.splice_event_id
    }
    /// <p>This is written to <code>splice_insert.unique_program_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn unique_program_id(&self) -> ::std::option::Option<i32> {
        self.unique_program_id
    }
}
impl SpliceInsertMessage {
    /// Creates a new builder-style object to manufacture [`SpliceInsertMessage`](crate::types::SpliceInsertMessage).
    pub fn builder() -> crate::types::builders::SpliceInsertMessageBuilder {
        crate::types::builders::SpliceInsertMessageBuilder::default()
    }
}

/// A builder for [`SpliceInsertMessage`](crate::types::SpliceInsertMessage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SpliceInsertMessageBuilder {
    pub(crate) avail_num: ::std::option::Option<i32>,
    pub(crate) avails_expected: ::std::option::Option<i32>,
    pub(crate) splice_event_id: ::std::option::Option<i32>,
    pub(crate) unique_program_id: ::std::option::Option<i32>,
}
impl SpliceInsertMessageBuilder {
    /// <p>This is written to <code>splice_insert.avail_num</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn avail_num(mut self, input: i32) -> Self {
        self.avail_num = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is written to <code>splice_insert.avail_num</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn set_avail_num(mut self, input: ::std::option::Option<i32>) -> Self {
        self.avail_num = input;
        self
    }
    /// <p>This is written to <code>splice_insert.avail_num</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn get_avail_num(&self) -> &::std::option::Option<i32> {
        &self.avail_num
    }
    /// <p>This is written to <code>splice_insert.avails_expected</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn avails_expected(mut self, input: i32) -> Self {
        self.avails_expected = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is written to <code>splice_insert.avails_expected</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn set_avails_expected(mut self, input: ::std::option::Option<i32>) -> Self {
        self.avails_expected = input;
        self
    }
    /// <p>This is written to <code>splice_insert.avails_expected</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn get_avails_expected(&self) -> &::std::option::Option<i32> {
        &self.avails_expected
    }
    /// <p>This is written to <code>splice_insert.splice_event_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>1</code>.</p>
    pub fn splice_event_id(mut self, input: i32) -> Self {
        self.splice_event_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is written to <code>splice_insert.splice_event_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>1</code>.</p>
    pub fn set_splice_event_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.splice_event_id = input;
        self
    }
    /// <p>This is written to <code>splice_insert.splice_event_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>1</code>.</p>
    pub fn get_splice_event_id(&self) -> &::std::option::Option<i32> {
        &self.splice_event_id
    }
    /// <p>This is written to <code>splice_insert.unique_program_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn unique_program_id(mut self, input: i32) -> Self {
        self.unique_program_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is written to <code>splice_insert.unique_program_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn set_unique_program_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.unique_program_id = input;
        self
    }
    /// <p>This is written to <code>splice_insert.unique_program_id</code>, as defined in section 9.7.3.1 of the SCTE-35 specification. The default value is <code>0</code>. Values must be between <code>0</code> and <code>256</code>, inclusive.</p>
    pub fn get_unique_program_id(&self) -> &::std::option::Option<i32> {
        &self.unique_program_id
    }
    /// Consumes the builder and constructs a [`SpliceInsertMessage`](crate::types::SpliceInsertMessage).
    pub fn build(self) -> crate::types::SpliceInsertMessage {
        crate::types::SpliceInsertMessage {
            avail_num: self.avail_num,
            avails_expected: self.avails_expected,
            splice_event_id: self.splice_event_id,
            unique_program_id: self.unique_program_id,
        }
    }
}
