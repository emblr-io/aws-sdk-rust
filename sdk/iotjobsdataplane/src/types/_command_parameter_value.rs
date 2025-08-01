// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The list of values used to describe a specific command parameter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CommandParameterValue {
    /// <p>An attribute of type String. For example:</p>
    /// <p><code>"S": "Hello"</code></p>
    pub s: ::std::option::Option<::std::string::String>,
    /// <p>An attribute of type Boolean. For example:</p>
    /// <p><code>"BOOL": true</code></p>
    pub b: ::std::option::Option<bool>,
    /// <p>An attribute of type Integer (Thirty-Two Bits).</p>
    pub i: ::std::option::Option<i32>,
    /// <p>An attribute of type Long.</p>
    pub l: ::std::option::Option<i64>,
    /// <p>An attribute of type Double (Sixty-Four Bits).</p>
    pub d: ::std::option::Option<f64>,
    /// <p>An attribute of type Binary.</p>
    pub bin: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>An attribute of type Unsigned Long.</p>
    pub ul: ::std::option::Option<::std::string::String>,
}
impl CommandParameterValue {
    /// <p>An attribute of type String. For example:</p>
    /// <p><code>"S": "Hello"</code></p>
    pub fn s(&self) -> ::std::option::Option<&str> {
        self.s.as_deref()
    }
    /// <p>An attribute of type Boolean. For example:</p>
    /// <p><code>"BOOL": true</code></p>
    pub fn b(&self) -> ::std::option::Option<bool> {
        self.b
    }
    /// <p>An attribute of type Integer (Thirty-Two Bits).</p>
    pub fn i(&self) -> ::std::option::Option<i32> {
        self.i
    }
    /// <p>An attribute of type Long.</p>
    pub fn l(&self) -> ::std::option::Option<i64> {
        self.l
    }
    /// <p>An attribute of type Double (Sixty-Four Bits).</p>
    pub fn d(&self) -> ::std::option::Option<f64> {
        self.d
    }
    /// <p>An attribute of type Binary.</p>
    pub fn bin(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.bin.as_ref()
    }
    /// <p>An attribute of type Unsigned Long.</p>
    pub fn ul(&self) -> ::std::option::Option<&str> {
        self.ul.as_deref()
    }
}
impl CommandParameterValue {
    /// Creates a new builder-style object to manufacture [`CommandParameterValue`](crate::types::CommandParameterValue).
    pub fn builder() -> crate::types::builders::CommandParameterValueBuilder {
        crate::types::builders::CommandParameterValueBuilder::default()
    }
}

/// A builder for [`CommandParameterValue`](crate::types::CommandParameterValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CommandParameterValueBuilder {
    pub(crate) s: ::std::option::Option<::std::string::String>,
    pub(crate) b: ::std::option::Option<bool>,
    pub(crate) i: ::std::option::Option<i32>,
    pub(crate) l: ::std::option::Option<i64>,
    pub(crate) d: ::std::option::Option<f64>,
    pub(crate) bin: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) ul: ::std::option::Option<::std::string::String>,
}
impl CommandParameterValueBuilder {
    /// <p>An attribute of type String. For example:</p>
    /// <p><code>"S": "Hello"</code></p>
    pub fn s(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An attribute of type String. For example:</p>
    /// <p><code>"S": "Hello"</code></p>
    pub fn set_s(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s = input;
        self
    }
    /// <p>An attribute of type String. For example:</p>
    /// <p><code>"S": "Hello"</code></p>
    pub fn get_s(&self) -> &::std::option::Option<::std::string::String> {
        &self.s
    }
    /// <p>An attribute of type Boolean. For example:</p>
    /// <p><code>"BOOL": true</code></p>
    pub fn b(mut self, input: bool) -> Self {
        self.b = ::std::option::Option::Some(input);
        self
    }
    /// <p>An attribute of type Boolean. For example:</p>
    /// <p><code>"BOOL": true</code></p>
    pub fn set_b(mut self, input: ::std::option::Option<bool>) -> Self {
        self.b = input;
        self
    }
    /// <p>An attribute of type Boolean. For example:</p>
    /// <p><code>"BOOL": true</code></p>
    pub fn get_b(&self) -> &::std::option::Option<bool> {
        &self.b
    }
    /// <p>An attribute of type Integer (Thirty-Two Bits).</p>
    pub fn i(mut self, input: i32) -> Self {
        self.i = ::std::option::Option::Some(input);
        self
    }
    /// <p>An attribute of type Integer (Thirty-Two Bits).</p>
    pub fn set_i(mut self, input: ::std::option::Option<i32>) -> Self {
        self.i = input;
        self
    }
    /// <p>An attribute of type Integer (Thirty-Two Bits).</p>
    pub fn get_i(&self) -> &::std::option::Option<i32> {
        &self.i
    }
    /// <p>An attribute of type Long.</p>
    pub fn l(mut self, input: i64) -> Self {
        self.l = ::std::option::Option::Some(input);
        self
    }
    /// <p>An attribute of type Long.</p>
    pub fn set_l(mut self, input: ::std::option::Option<i64>) -> Self {
        self.l = input;
        self
    }
    /// <p>An attribute of type Long.</p>
    pub fn get_l(&self) -> &::std::option::Option<i64> {
        &self.l
    }
    /// <p>An attribute of type Double (Sixty-Four Bits).</p>
    pub fn d(mut self, input: f64) -> Self {
        self.d = ::std::option::Option::Some(input);
        self
    }
    /// <p>An attribute of type Double (Sixty-Four Bits).</p>
    pub fn set_d(mut self, input: ::std::option::Option<f64>) -> Self {
        self.d = input;
        self
    }
    /// <p>An attribute of type Double (Sixty-Four Bits).</p>
    pub fn get_d(&self) -> &::std::option::Option<f64> {
        &self.d
    }
    /// <p>An attribute of type Binary.</p>
    pub fn bin(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.bin = ::std::option::Option::Some(input);
        self
    }
    /// <p>An attribute of type Binary.</p>
    pub fn set_bin(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.bin = input;
        self
    }
    /// <p>An attribute of type Binary.</p>
    pub fn get_bin(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.bin
    }
    /// <p>An attribute of type Unsigned Long.</p>
    pub fn ul(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ul = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An attribute of type Unsigned Long.</p>
    pub fn set_ul(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ul = input;
        self
    }
    /// <p>An attribute of type Unsigned Long.</p>
    pub fn get_ul(&self) -> &::std::option::Option<::std::string::String> {
        &self.ul
    }
    /// Consumes the builder and constructs a [`CommandParameterValue`](crate::types::CommandParameterValue).
    pub fn build(self) -> crate::types::CommandParameterValue {
        crate::types::CommandParameterValue {
            s: self.s,
            b: self.b,
            i: self.i,
            l: self.l,
            d: self.d,
            bin: self.bin,
            ul: self.ul,
        }
    }
}
