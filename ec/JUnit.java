package kpp.ec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;

public class JUnit {

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@Test
	public void testECPoints() throws ECParamsIllegalException, PNotPrimeException, ECNotImplementedException {
		ECOverInt c = new ECOverInt(7, 1, 4);
		PointOnEC[] ps = { new PointOnEC(0, 2), new PointOnEC(0, 5), new PointOnEC(2, 0), new PointOnEC(4, 3),
				new PointOnEC(4, 4), new PointOnEC(5, 1), new PointOnEC(5, 6), new PointOnEC(6, 3), new PointOnEC(6, 4),
				new PointOnEC(8, 8) };

		for (PointOnEC p : ps) {
			assertTrue(c.checkPointOnEC(p));
		}
	}

	@Test
	public void testOrder() throws ECNotImplementedException, ECParamsIllegalException, PNotPrimeException {
		System.out.println("______");
		ECOverInt c = new ECOverInt(7, 1, 4);
		PointOnEC p1 = new PointOnEC(2, 0);
		PointOnEC p2 = new PointOnEC(0, 5);
		PointOnEC p3 = new PointOnEC(8, 8);

		System.out.println("> " + c.getOrderOfPoint(p1) + " == 2");
		assertEquals(c.getOrderOfPoint(p1), 2);
		System.out.println("> " + c.getOrderOfPoint(p2) + " == 10");
		assertEquals(c.getOrderOfPoint(p2), 10);
		System.out.println("> " + c.getOrderOfPoint(p3) + " == 1");
		assertEquals(c.getOrderOfPoint(p3), 1);
	}
}