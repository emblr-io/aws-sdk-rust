// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The display options for margins around the outside edge of sheets.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MarginStyle {
    /// <p>This Boolean value controls whether to display sheet margins.</p>
    pub show: ::std::option::Option<bool>,
}
impl MarginStyle {
    /// <p>This Boolean value controls whether to display sheet margins.</p>
    pub fn show(&self) -> ::std::option::Option<bool> {
        self.show
    }
}
impl MarginStyle {
    /// Creates a new builder-style object to manufacture [`MarginStyle`](crate::types::MarginStyle).
    pub fn builder() -> crate::types::builders::MarginStyleBuilder {
        crate::types::builders::MarginStyleBuilder::default()
    }
}

/// A builder for [`MarginStyle`](crate::types::MarginStyle).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MarginStyleBuilder {
    pub(crate) show: ::std::option::Option<bool>,
}
impl MarginStyleBuilder {
    /// <p>This Boolean value controls whether to display sheet margins.</p>
    pub fn show(mut self, input: bool) -> Self {
        self.show = ::std::option::Option::Some(input);
        self
    }
    /// <p>This Boolean value controls whether to display sheet margins.</p>
    pub fn set_show(mut self, input: ::std::option::Option<bool>) -> Self {
        self.show = input;
        self
    }
    /// <p>This Boolean value controls whether to display sheet margins.</p>
    pub fn get_show(&self) -> &::std::option::Option<bool> {
        &self.show
    }
    /// Consumes the builder and constructs a [`MarginStyle`](crate::types::MarginStyle).
    pub fn build(self) -> crate::types::MarginStyle {
        crate::types::MarginStyle { show: self.show }
    }
}
