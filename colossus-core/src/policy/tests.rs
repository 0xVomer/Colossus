use super::*;

#[test]
fn test_edit_anarchic_attributes() {
    use super::QualifiedAttribute;

    let mut structure = AccessStructure::new();
    gen_test_structure(&mut structure, false).unwrap();

    assert_eq!(structure.attributes().count(), 7);

    assert!(
        structure
            .update_attribute(
                &QualifiedAttribute::new("DPT", "RD"),
                QualifiedAttribute::new("DPT", "MKG").bytes(),
            )
            .is_err()
    );

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

    let new_attr = QualifiedAttribute::new("DPT", "Sales");
    assert!(structure.add_attribute(new_attr.clone(), None).is_ok());
    assert_eq!(structure.attributes().count(), 8);

    let duplicate_attr = QualifiedAttribute::new("DPT", "HR");
    assert!(structure.add_attribute(duplicate_attr, None).is_err());

    let missing_dimension = QualifiedAttribute::new("Missing", "dimension");
    assert!(structure.add_attribute(missing_dimension.clone(), None).is_err());

    let delete_attr = QualifiedAttribute::new("DPT", "Research");
    structure.del_attribute(&delete_attr).unwrap();
    assert_eq!(structure.attributes().count(), 7);

    assert!(structure.del_attribute(&delete_attr).is_err());

    assert!(structure.del_attribute(&missing_dimension).is_err());

    structure.del_attribute(&new_attr).unwrap();
    structure.del_attribute(&QualifiedAttribute::new("DPT", "HR")).unwrap();
    structure.del_attribute(&QualifiedAttribute::new("DPT", "MKG")).unwrap();

    structure.del_dimension("DPT").unwrap();

    assert_eq!(structure.dimensions().count(), 1);

    structure.add_anarchy("DimensionTest".to_string()).unwrap();
    structure
        .add_attribute(QualifiedAttribute::new("DimensionTest", "Attr1"), None)
        .unwrap();
    structure
        .add_attribute(QualifiedAttribute::new("DimensionTest", "Attr2"), None)
        .unwrap();
    assert_eq!(structure.dimensions().count(), 2);

    structure.del_dimension("DimensionTest").unwrap();
    assert_eq!(structure.dimensions().count(), 1);

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

    structure.del_dimension("SEC").unwrap();
}
