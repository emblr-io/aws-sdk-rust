// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information for required items of personal protective equipment (PPE) detected on persons by a call to <code>DetectProtectiveEquipment</code>. You specify the required type of PPE in the <code>SummarizationAttributes</code> (<code>ProtectiveEquipmentSummarizationAttributes</code>) input parameter. The summary includes which persons were detected wearing the required personal protective equipment (<code>PersonsWithRequiredEquipment</code>), which persons were detected as not wearing the required PPE (<code>PersonsWithoutRequiredEquipment</code>), and the persons in which a determination could not be made (<code>PersonsIndeterminate</code>).</p>
/// <p>To get a total for each category, use the size of the field array. For example, to find out how many people were detected as wearing the specified PPE, use the size of the <code>PersonsWithRequiredEquipment</code> array. If you want to find out more about a person, such as the location (<code>BoundingBox</code>) of the person on the image, use the person ID in each array element. Each person ID matches the ID field of a <code>ProtectiveEquipmentPerson</code> object returned in the <code>Persons</code> array by <code>DetectProtectiveEquipment</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProtectiveEquipmentSummary {
    /// <p>An array of IDs for persons who are wearing detected personal protective equipment.</p>
    pub persons_with_required_equipment: ::std::option::Option<::std::vec::Vec<i32>>,
    /// <p>An array of IDs for persons who are not wearing all of the types of PPE specified in the <code>RequiredEquipmentTypes</code> field of the detected personal protective equipment.</p>
    pub persons_without_required_equipment: ::std::option::Option<::std::vec::Vec<i32>>,
    /// <p>An array of IDs for persons where it was not possible to determine if they are wearing personal protective equipment.</p>
    pub persons_indeterminate: ::std::option::Option<::std::vec::Vec<i32>>,
}
impl ProtectiveEquipmentSummary {
    /// <p>An array of IDs for persons who are wearing detected personal protective equipment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.persons_with_required_equipment.is_none()`.
    pub fn persons_with_required_equipment(&self) -> &[i32] {
        self.persons_with_required_equipment.as_deref().unwrap_or_default()
    }
    /// <p>An array of IDs for persons who are not wearing all of the types of PPE specified in the <code>RequiredEquipmentTypes</code> field of the detected personal protective equipment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.persons_without_required_equipment.is_none()`.
    pub fn persons_without_required_equipment(&self) -> &[i32] {
        self.persons_without_required_equipment.as_deref().unwrap_or_default()
    }
    /// <p>An array of IDs for persons where it was not possible to determine if they are wearing personal protective equipment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.persons_indeterminate.is_none()`.
    pub fn persons_indeterminate(&self) -> &[i32] {
        self.persons_indeterminate.as_deref().unwrap_or_default()
    }
}
impl ProtectiveEquipmentSummary {
    /// Creates a new builder-style object to manufacture [`ProtectiveEquipmentSummary`](crate::types::ProtectiveEquipmentSummary).
    pub fn builder() -> crate::types::builders::ProtectiveEquipmentSummaryBuilder {
        crate::types::builders::ProtectiveEquipmentSummaryBuilder::default()
    }
}

/// A builder for [`ProtectiveEquipmentSummary`](crate::types::ProtectiveEquipmentSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProtectiveEquipmentSummaryBuilder {
    pub(crate) persons_with_required_equipment: ::std::option::Option<::std::vec::Vec<i32>>,
    pub(crate) persons_without_required_equipment: ::std::option::Option<::std::vec::Vec<i32>>,
    pub(crate) persons_indeterminate: ::std::option::Option<::std::vec::Vec<i32>>,
}
impl ProtectiveEquipmentSummaryBuilder {
    /// Appends an item to `persons_with_required_equipment`.
    ///
    /// To override the contents of this collection use [`set_persons_with_required_equipment`](Self::set_persons_with_required_equipment).
    ///
    /// <p>An array of IDs for persons who are wearing detected personal protective equipment.</p>
    pub fn persons_with_required_equipment(mut self, input: i32) -> Self {
        let mut v = self.persons_with_required_equipment.unwrap_or_default();
        v.push(input);
        self.persons_with_required_equipment = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of IDs for persons who are wearing detected personal protective equipment.</p>
    pub fn set_persons_with_required_equipment(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.persons_with_required_equipment = input;
        self
    }
    /// <p>An array of IDs for persons who are wearing detected personal protective equipment.</p>
    pub fn get_persons_with_required_equipment(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.persons_with_required_equipment
    }
    /// Appends an item to `persons_without_required_equipment`.
    ///
    /// To override the contents of this collection use [`set_persons_without_required_equipment`](Self::set_persons_without_required_equipment).
    ///
    /// <p>An array of IDs for persons who are not wearing all of the types of PPE specified in the <code>RequiredEquipmentTypes</code> field of the detected personal protective equipment.</p>
    pub fn persons_without_required_equipment(mut self, input: i32) -> Self {
        let mut v = self.persons_without_required_equipment.unwrap_or_default();
        v.push(input);
        self.persons_without_required_equipment = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of IDs for persons who are not wearing all of the types of PPE specified in the <code>RequiredEquipmentTypes</code> field of the detected personal protective equipment.</p>
    pub fn set_persons_without_required_equipment(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.persons_without_required_equipment = input;
        self
    }
    /// <p>An array of IDs for persons who are not wearing all of the types of PPE specified in the <code>RequiredEquipmentTypes</code> field of the detected personal protective equipment.</p>
    pub fn get_persons_without_required_equipment(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.persons_without_required_equipment
    }
    /// Appends an item to `persons_indeterminate`.
    ///
    /// To override the contents of this collection use [`set_persons_indeterminate`](Self::set_persons_indeterminate).
    ///
    /// <p>An array of IDs for persons where it was not possible to determine if they are wearing personal protective equipment.</p>
    pub fn persons_indeterminate(mut self, input: i32) -> Self {
        let mut v = self.persons_indeterminate.unwrap_or_default();
        v.push(input);
        self.persons_indeterminate = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of IDs for persons where it was not possible to determine if they are wearing personal protective equipment.</p>
    pub fn set_persons_indeterminate(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.persons_indeterminate = input;
        self
    }
    /// <p>An array of IDs for persons where it was not possible to determine if they are wearing personal protective equipment.</p>
    pub fn get_persons_indeterminate(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.persons_indeterminate
    }
    /// Consumes the builder and constructs a [`ProtectiveEquipmentSummary`](crate::types::ProtectiveEquipmentSummary).
    pub fn build(self) -> crate::types::ProtectiveEquipmentSummary {
        crate::types::ProtectiveEquipmentSummary {
            persons_with_required_equipment: self.persons_with_required_equipment,
            persons_without_required_equipment: self.persons_without_required_equipment,
            persons_indeterminate: self.persons_indeterminate,
        }
    }
}
