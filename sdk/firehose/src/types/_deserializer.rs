// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The deserializer you want Firehose to use for converting the input data from JSON. Firehose then serializes the data to its final format using the <code>Serializer</code>. Firehose supports two types of deserializers: the <a href="https://cwiki.apache.org/confluence/display/Hive/LanguageManual+DDL#LanguageManualDDL-JSON">Apache Hive JSON SerDe</a> and the <a href="https://github.com/rcongiu/Hive-JSON-Serde">OpenX JSON SerDe</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Deserializer {
    /// <p>The OpenX SerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the native Hive / HCatalog JsonSerDe.</p>
    pub open_x_json_ser_de: ::std::option::Option<crate::types::OpenXJsonSerDe>,
    /// <p>The native Hive / HCatalog JsonSerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the OpenX SerDe.</p>
    pub hive_json_ser_de: ::std::option::Option<crate::types::HiveJsonSerDe>,
}
impl Deserializer {
    /// <p>The OpenX SerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the native Hive / HCatalog JsonSerDe.</p>
    pub fn open_x_json_ser_de(&self) -> ::std::option::Option<&crate::types::OpenXJsonSerDe> {
        self.open_x_json_ser_de.as_ref()
    }
    /// <p>The native Hive / HCatalog JsonSerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the OpenX SerDe.</p>
    pub fn hive_json_ser_de(&self) -> ::std::option::Option<&crate::types::HiveJsonSerDe> {
        self.hive_json_ser_de.as_ref()
    }
}
impl Deserializer {
    /// Creates a new builder-style object to manufacture [`Deserializer`](crate::types::Deserializer).
    pub fn builder() -> crate::types::builders::DeserializerBuilder {
        crate::types::builders::DeserializerBuilder::default()
    }
}

/// A builder for [`Deserializer`](crate::types::Deserializer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeserializerBuilder {
    pub(crate) open_x_json_ser_de: ::std::option::Option<crate::types::OpenXJsonSerDe>,
    pub(crate) hive_json_ser_de: ::std::option::Option<crate::types::HiveJsonSerDe>,
}
impl DeserializerBuilder {
    /// <p>The OpenX SerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the native Hive / HCatalog JsonSerDe.</p>
    pub fn open_x_json_ser_de(mut self, input: crate::types::OpenXJsonSerDe) -> Self {
        self.open_x_json_ser_de = ::std::option::Option::Some(input);
        self
    }
    /// <p>The OpenX SerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the native Hive / HCatalog JsonSerDe.</p>
    pub fn set_open_x_json_ser_de(mut self, input: ::std::option::Option<crate::types::OpenXJsonSerDe>) -> Self {
        self.open_x_json_ser_de = input;
        self
    }
    /// <p>The OpenX SerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the native Hive / HCatalog JsonSerDe.</p>
    pub fn get_open_x_json_ser_de(&self) -> &::std::option::Option<crate::types::OpenXJsonSerDe> {
        &self.open_x_json_ser_de
    }
    /// <p>The native Hive / HCatalog JsonSerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the OpenX SerDe.</p>
    pub fn hive_json_ser_de(mut self, input: crate::types::HiveJsonSerDe) -> Self {
        self.hive_json_ser_de = ::std::option::Option::Some(input);
        self
    }
    /// <p>The native Hive / HCatalog JsonSerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the OpenX SerDe.</p>
    pub fn set_hive_json_ser_de(mut self, input: ::std::option::Option<crate::types::HiveJsonSerDe>) -> Self {
        self.hive_json_ser_de = input;
        self
    }
    /// <p>The native Hive / HCatalog JsonSerDe. Used by Firehose for deserializing data, which means converting it from the JSON format in preparation for serializing it to the Parquet or ORC format. This is one of two deserializers you can choose, depending on which one offers the functionality you need. The other option is the OpenX SerDe.</p>
    pub fn get_hive_json_ser_de(&self) -> &::std::option::Option<crate::types::HiveJsonSerDe> {
        &self.hive_json_ser_de
    }
    /// Consumes the builder and constructs a [`Deserializer`](crate::types::Deserializer).
    pub fn build(self) -> crate::types::Deserializer {
        crate::types::Deserializer {
            open_x_json_ser_de: self.open_x_json_ser_de,
            hive_json_ser_de: self.hive_json_ser_de,
        }
    }
}
