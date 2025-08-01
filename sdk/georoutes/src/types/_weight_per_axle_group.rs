// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the total weight for the specified axle group. Meant for usage in countries that have different regulations based on the axle group type.</p>
/// <p><b>Unit</b>: <code>Kilograms</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WeightPerAxleGroup {
    /// <p>Weight for single axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub single: i64,
    /// <p>Weight for tandem axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub tandem: i64,
    /// <p>Weight for triple axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub triple: i64,
    /// <p>Weight for quad axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub quad: i64,
    /// <p>Weight for quad quint group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub quint: i64,
}
impl WeightPerAxleGroup {
    /// <p>Weight for single axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn single(&self) -> i64 {
        self.single
    }
    /// <p>Weight for tandem axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn tandem(&self) -> i64 {
        self.tandem
    }
    /// <p>Weight for triple axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn triple(&self) -> i64 {
        self.triple
    }
    /// <p>Weight for quad axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn quad(&self) -> i64 {
        self.quad
    }
    /// <p>Weight for quad quint group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn quint(&self) -> i64 {
        self.quint
    }
}
impl WeightPerAxleGroup {
    /// Creates a new builder-style object to manufacture [`WeightPerAxleGroup`](crate::types::WeightPerAxleGroup).
    pub fn builder() -> crate::types::builders::WeightPerAxleGroupBuilder {
        crate::types::builders::WeightPerAxleGroupBuilder::default()
    }
}

/// A builder for [`WeightPerAxleGroup`](crate::types::WeightPerAxleGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WeightPerAxleGroupBuilder {
    pub(crate) single: ::std::option::Option<i64>,
    pub(crate) tandem: ::std::option::Option<i64>,
    pub(crate) triple: ::std::option::Option<i64>,
    pub(crate) quad: ::std::option::Option<i64>,
    pub(crate) quint: ::std::option::Option<i64>,
}
impl WeightPerAxleGroupBuilder {
    /// <p>Weight for single axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn single(mut self, input: i64) -> Self {
        self.single = ::std::option::Option::Some(input);
        self
    }
    /// <p>Weight for single axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn set_single(mut self, input: ::std::option::Option<i64>) -> Self {
        self.single = input;
        self
    }
    /// <p>Weight for single axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn get_single(&self) -> &::std::option::Option<i64> {
        &self.single
    }
    /// <p>Weight for tandem axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn tandem(mut self, input: i64) -> Self {
        self.tandem = ::std::option::Option::Some(input);
        self
    }
    /// <p>Weight for tandem axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn set_tandem(mut self, input: ::std::option::Option<i64>) -> Self {
        self.tandem = input;
        self
    }
    /// <p>Weight for tandem axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn get_tandem(&self) -> &::std::option::Option<i64> {
        &self.tandem
    }
    /// <p>Weight for triple axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn triple(mut self, input: i64) -> Self {
        self.triple = ::std::option::Option::Some(input);
        self
    }
    /// <p>Weight for triple axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn set_triple(mut self, input: ::std::option::Option<i64>) -> Self {
        self.triple = input;
        self
    }
    /// <p>Weight for triple axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn get_triple(&self) -> &::std::option::Option<i64> {
        &self.triple
    }
    /// <p>Weight for quad axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn quad(mut self, input: i64) -> Self {
        self.quad = ::std::option::Option::Some(input);
        self
    }
    /// <p>Weight for quad axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn set_quad(mut self, input: ::std::option::Option<i64>) -> Self {
        self.quad = input;
        self
    }
    /// <p>Weight for quad axle group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn get_quad(&self) -> &::std::option::Option<i64> {
        &self.quad
    }
    /// <p>Weight for quad quint group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn quint(mut self, input: i64) -> Self {
        self.quint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Weight for quad quint group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn set_quint(mut self, input: ::std::option::Option<i64>) -> Self {
        self.quint = input;
        self
    }
    /// <p>Weight for quad quint group.</p>
    /// <p><b>Unit</b>: <code>Kilograms</code></p>
    pub fn get_quint(&self) -> &::std::option::Option<i64> {
        &self.quint
    }
    /// Consumes the builder and constructs a [`WeightPerAxleGroup`](crate::types::WeightPerAxleGroup).
    pub fn build(self) -> crate::types::WeightPerAxleGroup {
        crate::types::WeightPerAxleGroup {
            single: self.single.unwrap_or_default(),
            tandem: self.tandem.unwrap_or_default(),
            triple: self.triple.unwrap_or_default(),
            quad: self.quad.unwrap_or_default(),
            quint: self.quint.unwrap_or_default(),
        }
    }
}
