from unittest import TestCase

from buidl.pecc import FieldElement, Point


class FieldElementTest(TestCase):
    def test_ne(self):
        a = FieldElement(2, 31)
        b = FieldElement(2, 31)
        c = FieldElement(15, 31)
        self.assertEqual(a, b)
        self.assertTrue(a != c)
        self.assertFalse(a != b)

    def test_add(self):
        a = FieldElement(2, 31)
        b = FieldElement(15, 31)
        self.assertEqual(a + b, FieldElement(17, 31))
        a = FieldElement(17, 31)
        b = FieldElement(21, 31)
        self.assertEqual(a + b, FieldElement(7, 31))

    def test_sub(self):
        a = FieldElement(29, 31)
        b = FieldElement(4, 31)
        self.assertEqual(a - b, FieldElement(25, 31))
        a = FieldElement(15, 31)
        b = FieldElement(30, 31)
        self.assertEqual(a - b, FieldElement(16, 31))

    def test_mul(self):
        a = FieldElement(24, 31)
        b = FieldElement(19, 31)
        self.assertEqual(a * b, FieldElement(22, 31))

    def test_pow(self):
        a = FieldElement(17, 31)
        self.assertEqual(a ** 3, FieldElement(15, 31))
        a = FieldElement(5, 31)
        b = FieldElement(18, 31)
        self.assertEqual(a ** 5 * b, FieldElement(16, 31))

    def test_div(self):
        a = FieldElement(3, 31)
        b = FieldElement(24, 31)
        self.assertEqual(a / b, FieldElement(4, 31))
        a = FieldElement(17, 31)
        self.assertEqual(a ** -3, FieldElement(29, 31))
        a = FieldElement(4, 31)
        b = FieldElement(11, 31)
        self.assertEqual(a ** -4 * b, FieldElement(13, 31))


class PointTest(TestCase):
    def test_ne(self):
        a = Point(x=3, y=-7, a=5, b=7)
        b = Point(x=18, y=77, a=5, b=7)
        self.assertTrue(a != b)
        self.assertFalse(a != a)

    def test_on_curve(self):
        with self.assertRaises(ValueError):
            Point(x=-2, y=4, a=5, b=7)
        # these should not raise an error
        Point(x=3, y=-7, a=5, b=7)
        Point(x=18, y=77, a=5, b=7)

    def test_add0(self):
        a = Point(x=None, y=None, a=5, b=7)
        b = Point(x=2, y=5, a=5, b=7)
        c = Point(x=2, y=-5, a=5, b=7)
        self.assertEqual(a + b, b)
        self.assertEqual(b + a, b)
        self.assertEqual(b + c, a)

    def test_add1(self):
        a = Point(x=3, y=7, a=5, b=7)
        b = Point(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + b, Point(x=2, y=-5, a=5, b=7))

    def test_add2(self):
        a = Point(x=-1, y=1, a=5, b=7)
        self.assertEqual(a + a, Point(x=18, y=-77, a=5, b=7))


class ECCTest(TestCase):
    def test_on_curve(self):
        # tests the following points whether they are on the curve or not
        # on curve y^2=x^3-7 over F_223:
        # (192,105) (17,56) (200,119) (1,193) (42,99)
        # the ones that aren't should raise a ValueError
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))

        # iterate over valid points
        for x_raw, y_raw in valid_points:
            # Initialize points this way:
            # x = FieldElement(x_raw, prime)
            # y = FieldElement(y_raw, prime)
            # Point(x, y, a, b)
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            # Creating the point should not result in an error
            Point(x, y, a, b)

        # iterate over invalid points
        for x_raw, y_raw in invalid_points:
            # Initialize points this way:
            # x = FieldElement(x_raw, prime)
            # y = FieldElement(y_raw, prime)
            # Point(x, y, a, b)
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            # check that creating the point results in a ValueError
            # with self.assertRaises(ValueError):
            #     Point(x, y, a, b)
            with self.assertRaises(ValueError):
                Point(x, y, a, b)

    def test_add(self):
        # tests the following additions on curve y^2=x^3-7 over F_223:
        # (192,105) + (17,56)
        # (47,71) + (117,141)
        # (143,98) + (76,66)
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        additions = (
            # (x1, y1, x2, y2, x3, y3)
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        )
        # iterate over the additions
        for x1_raw, y1_raw, x2_raw, y2_raw, x3_raw, y3_raw in additions:
            # Initialize points this way:
            # x1 = FieldElement(x1_raw, prime)
            # y1 = FieldElement(y1_raw, prime)
            # p1 = Point(x1, y1, a, b)
            # x2 = FieldElement(x2_raw, prime)
            # y2 = FieldElement(y2_raw, prime)
            # p2 = Point(x2, y2, a, b)
            # x3 = FieldElement(x3_raw, prime)
            # y3 = FieldElement(y3_raw, prime)
            # p3 = Point(x3, y3, a, b)
            x1 = FieldElement(x1_raw, prime)
            y1 = FieldElement(y1_raw, prime)
            p1 = Point(x1, y1, a, b)
            x2 = FieldElement(x2_raw, prime)
            y2 = FieldElement(y2_raw, prime)
            p2 = Point(x2, y2, a, b)
            x3 = FieldElement(x3_raw, prime)
            y3 = FieldElement(y3_raw, prime)
            p3 = Point(x3, y3, a, b)
            # check that p1 + p2 == p3
            self.assertEqual(p1 + p2, p3)

    def test_rmul(self):
        # tests the following scalar multiplications
        # 2*(192,105)
        # 2*(143,98)
        # 2*(47,71)
        # 4*(47,71)
        # 8*(47,71)
        # 21*(47,71)
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        multiplications = (
            # (coefficient, x1, y1, x2, y2)
            (2, 192, 105, 49, 71),
            (2, 143, 98, 64, 168),
            (2, 47, 71, 36, 111),
            (4, 47, 71, 194, 51),
            (8, 47, 71, 116, 55),
            (21, 47, 71, None, None),
        )

        # iterate over the multiplications
        for s, x1_raw, y1_raw, x2_raw, y2_raw in multiplications:
            # Initialize points this way:
            # x1 = FieldElement(x1_raw, prime)
            # y1 = FieldElement(y1_raw, prime)
            # p1 = Point(x1, y1, a, b)
            x1 = FieldElement(x1_raw, prime)
            y1 = FieldElement(y1_raw, prime)
            p1 = Point(x1, y1, a, b)
            # initialize the second point based on whether it's the point at infinity
            # x2 = FieldElement(x2_raw, prime)
            # y2 = FieldElement(y2_raw, prime)
            # p2 = Point(x2, y2, a, b)
            if x2_raw is None:
                p2 = Point(None, None, a, b)
            else:
                x2 = FieldElement(x2_raw, prime)
                y2 = FieldElement(y2_raw, prime)
                p2 = Point(x2, y2, a, b)
            # check that the product is equal to the expected point
            self.assertEqual(s * p1, p2)
