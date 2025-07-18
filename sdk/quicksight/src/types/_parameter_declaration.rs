// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The declaration definition of a parameter.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/quicksight/latest/user/parameters-in-quicksight.html">Parameters in Amazon QuickSight</a> in the <i>Amazon QuickSight User Guide</i>.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParameterDeclaration {
    /// <p>A parameter declaration for the <code>String</code> data type.</p>
    pub string_parameter_declaration: ::std::option::Option<crate::types::StringParameterDeclaration>,
    /// <p>A parameter declaration for the <code>Decimal</code> data type.</p>
    pub decimal_parameter_declaration: ::std::option::Option<crate::types::DecimalParameterDeclaration>,
    /// <p>A parameter declaration for the <code>Integer</code> data type.</p>
    pub integer_parameter_declaration: ::std::option::Option<crate::types::IntegerParameterDeclaration>,
    /// <p>A parameter declaration for the <code>DateTime</code> data type.</p>
    pub date_time_parameter_declaration: ::std::option::Option<crate::types::DateTimeParameterDeclaration>,
}
impl ParameterDeclaration {
    /// <p>A parameter declaration for the <code>String</code> data type.</p>
    pub fn string_parameter_declaration(&self) -> ::std::option::Option<&crate::types::StringParameterDeclaration> {
        self.string_parameter_declaration.as_ref()
    }
    /// <p>A parameter declaration for the <code>Decimal</code> data type.</p>
    pub fn decimal_parameter_declaration(&self) -> ::std::option::Option<&crate::types::DecimalParameterDeclaration> {
        self.decimal_parameter_declaration.as_ref()
    }
    /// <p>A parameter declaration for the <code>Integer</code> data type.</p>
    pub fn integer_parameter_declaration(&self) -> ::std::option::Option<&crate::types::IntegerParameterDeclaration> {
        self.integer_parameter_declaration.as_ref()
    }
    /// <p>A parameter declaration for the <code>DateTime</code> data type.</p>
    pub fn date_time_parameter_declaration(&self) -> ::std::option::Option<&crate::types::DateTimeParameterDeclaration> {
        self.date_time_parameter_declaration.as_ref()
    }
}
impl ParameterDeclaration {
    /// Creates a new builder-style object to manufacture [`ParameterDeclaration`](crate::types::ParameterDeclaration).
    pub fn builder() -> crate::types::builders::ParameterDeclarationBuilder {
        crate::types::builders::ParameterDeclarationBuilder::default()
    }
}

/// A builder for [`ParameterDeclaration`](crate::types::ParameterDeclaration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParameterDeclarationBuilder {
    pub(crate) string_parameter_declaration: ::std::option::Option<crate::types::StringParameterDeclaration>,
    pub(crate) decimal_parameter_declaration: ::std::option::Option<crate::types::DecimalParameterDeclaration>,
    pub(crate) integer_parameter_declaration: ::std::option::Option<crate::types::IntegerParameterDeclaration>,
    pub(crate) date_time_parameter_declaration: ::std::option::Option<crate::types::DateTimeParameterDeclaration>,
}
impl ParameterDeclarationBuilder {
    /// <p>A parameter declaration for the <code>String</code> data type.</p>
    pub fn string_parameter_declaration(mut self, input: crate::types::StringParameterDeclaration) -> Self {
        self.string_parameter_declaration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A parameter declaration for the <code>String</code> data type.</p>
    pub fn set_string_parameter_declaration(mut self, input: ::std::option::Option<crate::types::StringParameterDeclaration>) -> Self {
        self.string_parameter_declaration = input;
        self
    }
    /// <p>A parameter declaration for the <code>String</code> data type.</p>
    pub fn get_string_parameter_declaration(&self) -> &::std::option::Option<crate::types::StringParameterDeclaration> {
        &self.string_parameter_declaration
    }
    /// <p>A parameter declaration for the <code>Decimal</code> data type.</p>
    pub fn decimal_parameter_declaration(mut self, input: crate::types::DecimalParameterDeclaration) -> Self {
        self.decimal_parameter_declaration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A parameter declaration for the <code>Decimal</code> data type.</p>
    pub fn set_decimal_parameter_declaration(mut self, input: ::std::option::Option<crate::types::DecimalParameterDeclaration>) -> Self {
        self.decimal_parameter_declaration = input;
        self
    }
    /// <p>A parameter declaration for the <code>Decimal</code> data type.</p>
    pub fn get_decimal_parameter_declaration(&self) -> &::std::option::Option<crate::types::DecimalParameterDeclaration> {
        &self.decimal_parameter_declaration
    }
    /// <p>A parameter declaration for the <code>Integer</code> data type.</p>
    pub fn integer_parameter_declaration(mut self, input: crate::types::IntegerParameterDeclaration) -> Self {
        self.integer_parameter_declaration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A parameter declaration for the <code>Integer</code> data type.</p>
    pub fn set_integer_parameter_declaration(mut self, input: ::std::option::Option<crate::types::IntegerParameterDeclaration>) -> Self {
        self.integer_parameter_declaration = input;
        self
    }
    /// <p>A parameter declaration for the <code>Integer</code> data type.</p>
    pub fn get_integer_parameter_declaration(&self) -> &::std::option::Option<crate::types::IntegerParameterDeclaration> {
        &self.integer_parameter_declaration
    }
    /// <p>A parameter declaration for the <code>DateTime</code> data type.</p>
    pub fn date_time_parameter_declaration(mut self, input: crate::types::DateTimeParameterDeclaration) -> Self {
        self.date_time_parameter_declaration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A parameter declaration for the <code>DateTime</code> data type.</p>
    pub fn set_date_time_parameter_declaration(mut self, input: ::std::option::Option<crate::types::DateTimeParameterDeclaration>) -> Self {
        self.date_time_parameter_declaration = input;
        self
    }
    /// <p>A parameter declaration for the <code>DateTime</code> data type.</p>
    pub fn get_date_time_parameter_declaration(&self) -> &::std::option::Option<crate::types::DateTimeParameterDeclaration> {
        &self.date_time_parameter_declaration
    }
    /// Consumes the builder and constructs a [`ParameterDeclaration`](crate::types::ParameterDeclaration).
    pub fn build(self) -> crate::types::ParameterDeclaration {
        crate::types::ParameterDeclaration {
            string_parameter_declaration: self.string_parameter_declaration,
            decimal_parameter_declaration: self.decimal_parameter_declaration,
            integer_parameter_declaration: self.integer_parameter_declaration,
            date_time_parameter_declaration: self.date_time_parameter_declaration,
        }
    }
}
