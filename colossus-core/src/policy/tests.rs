use super::*;

#[test]
fn test_edit_anarchic_attributes() {
    use super::QualifiedAttribute;

    let mut structure = AccessStructure::new();
    gen_test_structure(&mut structure, false).unwrap();

    assert_eq!(structure.attributes().count(), 7);

    // Try renaming Research to already used name MKG
    assert!(
        structure
            .update_attribute(
                &QualifiedAttribute::new("DPT", "RD"),
                QualifiedAttribute::new("DPT", "MKG").bytes(),
            )
            .is_err()
    );

    // Rename RD to Research
    assert!(
        structure
            .update_attribute(
                &QualifiedAttribute::new("DPT", "RD"),
                QualifiedAttribute::new("DPT", "Research").bytes(),
            )
            .is_ok()
    );

    let order: Vec<_> = structure
        .attributes()
        .filter(|a| a.dimension.as_str() == "SEC")
        .map(|a| a.cid)
        .collect();

    assert!(order.len() == 2);

    // Add new attribute Sales
    let new_attr = QualifiedAttribute::new("DPT", "Sales");
    assert!(structure.add_attribute(new_attr.clone(), None).is_ok());
    assert_eq!(structure.attributes().count(), 8);

    // Try adding already existing attribute HR
    let duplicate_attr = QualifiedAttribute::new("DPT", "HR");
    assert!(structure.add_attribute(duplicate_attr, None).is_err());

    // Try adding attribute to non existing dimension
    let missing_dimension = QualifiedAttribute::new("Missing", "dimension");
    assert!(structure.add_attribute(missing_dimension.clone(), None).is_err());

    // Remove research attribute
    let delete_attr = QualifiedAttribute::new("DPT", "Research");
    structure.del_attribute(&delete_attr).unwrap();
    assert_eq!(structure.attributes().count(), 7);

    // Duplicate remove
    assert!(structure.del_attribute(&delete_attr).is_err());

    // Missing dimension remove
    assert!(structure.del_attribute(&missing_dimension).is_err());

    // Remove all attributes from a dimension
    structure.del_attribute(&new_attr).unwrap();
    structure.del_attribute(&QualifiedAttribute::new("DPT", "HR")).unwrap();
    structure.del_attribute(&QualifiedAttribute::new("DPT", "MKG")).unwrap();

    structure.del_dimension("DPT").unwrap();

    assert_eq!(structure.dimensions().count(), 1);

    // Add new dimension
    structure.add_anarchy("DimensionTest".to_string()).unwrap();
    structure
        .add_attribute(QualifiedAttribute::new("DimensionTest", "Attr1"), None)
        .unwrap();
    structure
        .add_attribute(QualifiedAttribute::new("DimensionTest", "Attr2"), None)
        .unwrap();
    assert_eq!(structure.dimensions().count(), 2);

    //// Remove the new dimension
    structure.del_dimension("DimensionTest").unwrap();
    assert_eq!(structure.dimensions().count(), 1);

    //// Try removing non existing dimension
    assert!(structure.del_dimension("MissingDim").is_err());
}

#[test]
fn test_edit_hierarchic_attributes() {
    use super::QualifiedAttribute;

    let mut structure = AccessStructure::new();
    gen_test_structure(&mut structure, false).unwrap();

    assert_eq!(
        structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
        vec![
            QualifiedAttribute::from(("SEC", "LOW")),
            QualifiedAttribute::from(("SEC", "TOP")),
        ]
    );

    // Rename ordered dimension
    assert!(
        structure
            .update_attribute(
                &QualifiedAttribute::new("SEC", "LOW"),
                QualifiedAttribute::new("SEC", "WOL").bytes(),
            )
            .is_ok()
    );

    let order = structure.attributes().map(|q| q.cid).collect::<Vec<_>>();
    assert!(order.contains(&QualifiedAttribute::new("SEC", "WOL").cid));
    assert!(!order.contains(&QualifiedAttribute::new("SEC", "LOW").cid));

    //// Try modifying hierarchical dimension
    structure.del_attribute(&QualifiedAttribute::new("SEC", "WOL")).unwrap();

    structure.add_attribute(QualifiedAttribute::new("SEC", "MID"), None).unwrap();

    assert_eq!(
        structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
        vec![
            QualifiedAttribute::from(("SEC", "MID")),
            QualifiedAttribute::from(("SEC", "TOP")),
        ]
    );

    structure.add_attribute(QualifiedAttribute::new("SEC", "LOW"), None).unwrap();

    assert_eq!(
        structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
        vec![
            QualifiedAttribute::from(("SEC", "LOW")),
            QualifiedAttribute::from(("SEC", "MID")),
            QualifiedAttribute::from(("SEC", "TOP")),
        ]
    );

    structure.del_attribute(&QualifiedAttribute::new("SEC", "MID")).unwrap();

    structure
        .add_attribute(QualifiedAttribute::new("SEC", "MID"), Some("LOW"))
        .unwrap();

    assert_eq!(
        structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
        vec![
            QualifiedAttribute::from(("SEC", "LOW")),
            QualifiedAttribute::from(("SEC", "MID")),
            QualifiedAttribute::from(("SEC", "TOP")),
        ]
    );

    //// Removing a hierarchical dimension is permitted
    structure.del_dimension("SEC").unwrap();
}
